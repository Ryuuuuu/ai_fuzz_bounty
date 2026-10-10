import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from fuzz_target_scout.models import RepoSnapshot
from fuzz_target_scout.policy import CURATED_EXTERNAL_POLICY_URLS, PolicyVerifier


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

    def _external_catalog(self, name: str, *, verified_on: str = "2026-10-10"):
        url = CURATED_EXTERNAL_POLICY_URLS[name]
        self.catalog.write_text(
            json.dumps({"entries": [{
                "full_name": name,
                "status": "verified",
                "security_url": url,
                "program_url": url,
                "last_verified": verified_on,
            }]}),
            encoding="utf-8",
        )
        return url

    def test_curated_external_policy_requires_live_paid_repository_scope(self):
        cases = [
            (
                "firoorg/firo",
                "Firo runs an ongoing vulnerability bounty program. "
                "The program covers vulnerabilities reproduced against "
                "the master branch of firoorg/firo. "
                "All bounties are paid in FIRO.",
            ),
            (
                "monero-project/monero",
                "Monero Project GitHub repositories are covered by a "
                "bounty reward. Bounty distribution is paid in XMR.",
            ),
        ]
        for name, live_text in cases:
            with self.subTest(name=name):
                url = self._external_catalog(name)
                target = repo(name, live_text)
                target.security_url = url
                verifier = PolicyVerifier(self.catalog)
                self.assertEqual(
                    verifier.verify(target, today=date(2026, 10, 10)).status,
                    "verified",
                )
                if name == "firoorg/firo":
                    target.security_text = live_text.replace("ongoing ", "")
                    self.assertEqual(
                        verifier.verify(
                            target, today=date(2026, 10, 10)
                        ).status,
                        "rejected",
                    )
                target.security_text = ""
                self.assertEqual(
                    verifier.verify(target, today=date(2026, 10, 10)).status,
                    "rejected",
                )
                target.security_text = (
                    "Vulnerability reports can be sent to project maintainers."
                )
                self.assertEqual(
                    verifier.verify(target, today=date(2026, 10, 10)).status,
                    "rejected",
                )

    def test_curated_external_policy_rejects_stale_or_changed_url(self):
        name = "firoorg/firo"
        url = self._external_catalog(name, verified_on="2026-01-01")
        target = repo(
            name,
            "Firo runs an ongoing vulnerability bounty program. "
            "The program covers vulnerabilities reproduced against "
            "the master branch of firoorg/firo. "
            "All bounties are paid in FIRO.",
        )
        target.security_url = url
        self.assertEqual(
            PolicyVerifier(self.catalog).verify(
                target, today=date(2026, 10, 10)
            ).status,
            "rejected",
        )
        self._external_catalog(name)
        target.security_url = "https://firo.org/guide/other.html"
        self.assertEqual(
            PolicyVerifier(self.catalog).verify(
                target, today=date(2026, 10, 10)
            ).status,
            "rejected",
        )

    def test_repository_own_no_bounty_policy_overrides_curated_page(self):
        name = "firoorg/firo"
        url = self._external_catalog(name)
        target = repo(
            name,
            "Firo runs an ongoing vulnerability bounty program. "
            "The program covers vulnerabilities reproduced against "
            "the master branch of firoorg/firo. "
            "All bounties are paid in FIRO.",
        )
        target.security_url = url
        target.repository_security_text = "We do not offer monetary bounties."
        self.assertEqual(
            PolicyVerifier(self.catalog).verify(
                target, today=date(2026, 10, 10)
            ).status,
            "rejected",
        )

    def test_google_oss_vrp_feed_adds_only_current_oss_scope(self):
        verifier = PolicyVerifier(self.catalog)
        feed = """
repository {
  url: "https://github.com/google/flatbuffers"
  tier: TIER_OT1
  product_vuln_scope: SCOPE_OSS_VRP
}
repository {
  url: "https://github.com/example/cloud-only"
  tier: TIER_OT1
  product_vuln_scope: SCOPE_CLOUD_VRP
}
repository {
  url: "https://example.com/not-github"
  tier: TIER_OT0
  product_vuln_scope: SCOPE_OSS_VRP
}
"""
        count = verifier.merge_google_oss_vrp_feed(
            feed,
            "https://bughunters.google.com/about/rules/open-source/example",
            verified_on=date(2026, 9, 15),
        )
        result = verifier.verify(
            repo("google/flatbuffers", "Report vulnerabilities through g.co/vulnz."),
            today=date(2026, 9, 15),
        )

        self.assertEqual(count, 1)
        self.assertEqual(result.status, "verified")
        self.assertIn("google/flatbuffers", verifier.catalog_names)
        self.assertNotIn("example/cloud-only", verifier.catalog_names)

    def test_meta_owner_policy_is_a_trusted_paid_program(self):
        verifier = PolicyVerifier(self.catalog)
        assessment = verifier.verify(
            RepoSnapshot(
                full_name="facebook/folly",
                html_url="https://github.com/facebook/folly",
                default_branch="main",
                head_sha="abc",
                security_url="https://github.com/facebook/.github/blob/main/SECURITY.md",
                security_text=(
                    "Security issues in this open source project can be safely reported "
                    "via the Meta Bug Bounty program: https://www.facebook.com/whitehat. "
                    "Meta will determine whether it is eligible for a bounty."
                ),
            )
        )

        self.assertEqual(assessment.status, "verified")
        self.assertEqual(assessment.program_url, "https://www.facebook.com/whitehat")

    def test_repository_readme_exclusion_overrides_inherited_meta_policy(self):
        verifier = PolicyVerifier(self.catalog)
        target = RepoSnapshot(
            full_name="facebookincubator/bpfjailer",
            html_url="https://github.com/facebookincubator/bpfjailer",
            default_branch="main",
            head_sha="a" * 40,
            security_url="https://github.com/facebookincubator/.github/blob/main/SECURITY.md",
            security_text=(
                "Security issues in this open source project can be reported "
                "through the Meta Bug Bounty program at https://www.facebook.com/whitehat. "
                "They might fetch a bounty."
            ),
            readme_excerpt=(
                "**This project is experimental. Issues are expected and\n"
                "are not eligible for bug bounty or considered security findings.**"
            ),
        )

        self.assertEqual(verifier.verify(target).status, "rejected")
        self.assertEqual(verifier.verify(target).source, "readme")

    def test_report_class_exclusion_does_not_reject_entire_repository(self):
        verifier = PolicyVerifier(self.catalog)
        target = RepoSnapshot(
            full_name="facebook/example",
            html_url="https://github.com/facebook/example",
            default_branch="main",
            head_sha="a" * 40,
            security_url="https://github.com/facebook/.github/blob/main/SECURITY.md",
            security_text=(
                "This project has a bug bounty program at "
                "https://www.facebook.com/whitehat."
            ),
            readme_excerpt="Known issues are not eligible for a bug bounty.",
        )

        self.assertEqual(verifier.verify(target).status, "verified")

    def test_direct_explicit_bounty_is_verified(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo(
                "example/parser",
                "This project has a public bug bounty program at "
                "https://hackerone.com/example",
            )
        )
        self.assertEqual(result.status, "verified")

    def test_submission_route_can_override_other_non_bounty_route(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo(
                "example/tool",
                "Private repository reports are not eligible for a bounty. "
                "Submit through https://hackerone.com/example to be eligible "
                "for a bounty reward.",
            )
        )
        self.assertEqual(result.status, "verified")

    def test_unlisted_owner_default_policy_does_not_prove_repository_scope(self):
        verifier = PolicyVerifier(self.catalog)
        assessment = verifier.verify(
            RepoSnapshot(
                full_name="microsoft/unlisted-project",
                html_url="https://github.com/microsoft/unlisted-project",
                default_branch="main",
                head_sha="abc",
                security_url="https://github.com/microsoft/.github/blob/main/SECURITY.md",
                security_text=(
                    "This project has a public bug bounty program at "
                    "https://www.microsoft.com/en-us/msrc/bounty"
                ),
            )
        )

        self.assertEqual(assessment.status, "needs_review")

    def test_copied_paid_policy_does_not_prove_repository_scope(self):
        verifier = PolicyVerifier(self.catalog)
        result = verifier.verify(
            repo(
                "unrelated/copy",
                "This project has a public bug bounty program at "
                "https://hackerone.com/coinbase",
            )
        )
        self.assertEqual(result.status, "needs_review")
        self.assertIn("copied policy", result.note)

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
                            "full_name": "example/tool",
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
                "example/tool",
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

    def test_google_oss_vrp_product_pause_blocks_new_fuzzing_candidates(self):
        verifier = PolicyVerifier(self.catalog)
        verifier.merge_google_oss_vrp_feed(
            'repository { url: "https://github.com/google/flatbuffers" '
            'tier: TIER_OT1 product_vuln_scope: SCOPE_OSS_VRP }',
            "https://bughunters.google.com/about/rules/open-source/"
            "google-open-source-software-vulnerability-reward-program-rules",
            verified_on=date(2026, 9, 30),
        )
        target = repo("google/flatbuffers", "Report vulnerabilities through g.co/vulnz.")

        self.assertEqual(verifier.verify(target, today=date(2026, 9, 30)).status, "verified")
        paused = verifier.verify(target, today=date(2026, 10, 1))
        self.assertEqual(paused.status, "rejected")
        self.assertEqual(paused.source, "google_oss_vrp")

    def test_google_oss_vrp_feed_does_not_reverify_paused_product_targets(self):
        verifier = PolicyVerifier(self.catalog)
        feed = (
            "repository { url: \"https://github.com/google/flatbuffers\" "
            "tier: TIER_OT1 product_vuln_scope: SCOPE_OSS_VRP }"
        )
        program_url = (
            "https://bughunters.google.com/about/rules/open-source/"
            "google-open-source-software-vulnerability-reward-program-rules"
        )
        self.assertEqual(
            verifier.merge_google_oss_vrp_feed(
                feed, program_url, verified_on=date(2026, 9, 30)
            ),
            1,
        )
        verifier.entries["google/flatbuffers"]["status"] = "rejected"
        self.assertEqual(
            verifier.merge_google_oss_vrp_feed(
                feed, program_url, verified_on=date(2026, 10, 1)
            ),
            1,
        )
        self.assertEqual(verifier.entries["google/flatbuffers"]["status"], "rejected")
        self.assertEqual(
            verifier.verify(
                repo("google/flatbuffers", "Report vulnerabilities through g.co/vulnz."),
                today=date(2026, 10, 10),
            ).status,
            "rejected",
        )

    def test_google_oss_vrp_pause_does_not_block_a_separate_paid_program(self):
        verifier = PolicyVerifier(self.catalog)
        verifier.merge_google_oss_vrp_feed(
            'repository { url: "https://github.com/google/flatbuffers" '
            'tier: TIER_OT1 product_vuln_scope: SCOPE_OSS_VRP }',
            "https://bughunters.google.com/about/rules/open-source/"
            "google-open-source-software-vulnerability-reward-program-rules",
            verified_on=date(2026, 10, 1),
        )
        target = repo(
            "google/flatbuffers",
            "This project has a public bug bounty program at https://hackerone.com/google.",
        )

        assessment = verifier.verify(target, today=date(2026, 10, 1))
        self.assertEqual(assessment.status, "verified")
        self.assertEqual(assessment.program_url, "https://hackerone.com/google")

    def test_google_oss_vrp_pause_is_limited_to_oss_product_program_url(self):
        self.catalog.write_text(
            json.dumps({"entries": [{
                "full_name": "google/other",
                "status": "verified",
                "security_url": "https://github.com/google/other/security/policy",
                "program_url": "https://bughunters.google.com/about/rules/google-cloud-vrp",
                "last_verified": "2026-10-01",
            }]}),
            encoding="utf-8",
        )
        verifier = PolicyVerifier(self.catalog)
        target = repo("google/other", "Report vulnerabilities through the current program.")

        self.assertEqual(verifier.verify(target, today=date(2026, 10, 1)).status, "verified")


if __name__ == "__main__":
    unittest.main()
