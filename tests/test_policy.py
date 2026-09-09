import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from fuzz_target_scout.models import RepoSnapshot
from fuzz_target_scout.policy import PolicyVerifier


def repo(name: str, security_text: str) -> RepoSnapshot:
    return RepoSnapshot(
        full_name=name,
        html_url=f"https://github.com/{name}",
        default_branch="main",
        head_sha="abc",
        security_url=f"https://github.com/{name}/security/policy",
        security_text=security_text,
    )


class PolicyVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.catalog = Path(self.temp.name) / "catalog.json"
        self.catalog.write_text('{"entries":[]}', encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_direct_explicit_bounty_is_verified(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo(
                "small/parser",
                "This project has a public bug bounty program at "
                "https://hackerone.com/example",
            )
        )
        self.assertEqual(result.status, "verified")

    def test_submission_route_can_override_other_non_bounty_route(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo(
                "cli/tool",
                "Private repository reports are not eligible for a bounty. "
                "Submit through https://hackerone.com/example to be eligible "
                "for a bounty reward.",
            )
        )
        self.assertEqual(result.status, "verified")

    def test_platform_link_without_exact_paid_scope_needs_review(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo("org/tool", "Report security issues at https://bugcrowd.com/example")
        )
        self.assertEqual(result.status, "needs_review")

    def test_explicit_no_bounty_is_rejected(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo("org/tool", "We do not offer monetary bounties for security reports.")
        )
        self.assertEqual(result.status, "rejected")

    def test_stale_catalog_never_auto_verifies(self):
        self.catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "full_name": "org/tool",
                            "status": "verified",
                            "program_url": "https://hackerone.com/example",
                            "last_verified": "2025-01-01",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        verifier = PolicyVerifier(self.catalog, max_age_days=45)
        result = verifier.verify(
            repo("org/tool", "Security reports: https://hackerone.com/example"),
            today=date(2026, 9, 9),
        )
        self.assertEqual(result.status, "needs_review")

    def test_stale_catalog_can_use_current_explicit_repository_policy(self):
        self.catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "full_name": "org/tool",
                            "status": "verified",
                            "program_url": "https://hackerone.com/example",
                            "last_verified": "2025-01-01",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        verifier = PolicyVerifier(self.catalog, max_age_days=45)
        result = verifier.verify(
            repo(
                "org/tool",
                "This repository has a public bug bounty program at "
                "https://hackerone.com/example",
            ),
            today=date(2026, 9, 9),
        )
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.source, "security.md")

    def test_current_no_bounty_text_overrides_fresh_catalog(self):
        self.catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "full_name": "org/tool",
                            "status": "verified",
                            "program_url": "https://hackerone.com/example",
                            "last_verified": "2026-09-09",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        verifier = PolicyVerifier(self.catalog, max_age_days=45)
        result = verifier.verify(
            repo("org/tool", "We do not offer monetary bounties."),
            today=date(2026, 9, 9),
        )
        self.assertEqual(result.status, "rejected")


if __name__ == "__main__":
    unittest.main()
