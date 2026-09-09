# Ubuntu 설치

지원 기준은 Ubuntu 24.04, Python 3.11 이상, Git, Docker Engine과 로그인된 Codex
CLI다. WSL2의 Ubuntu 24.04와 일반 Ubuntu 서버에서 같은 절차를 사용한다.

```bash
git clone https://github.com/Ryuuuuu/ai_fuzz_bounty.git
cd ai_fuzz_bounty
./scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
fts doctor
fts ai-check
fuzz-pipeline doctor
```

반복 GitHub 탐색에는 읽기 전용 토큰을 현재 셸 환경에만 둔다.

```bash
export GITHUB_TOKEN='github_pat_...'
```

Codex CLI 로그인 세션을 사용하므로 OpenAI API 키는 필요하지 않다. 기본 모델은
`gpt-daybreak-blue-latest`, 추론 강도는 `high`다.

릴리스 wheel을 설치할 때는 별도 가상환경을 사용한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install fuzz_target_scout-0.5.0-py3-none-any.whl
fuzz-pipeline doctor
```

Docker 소켓 권한이 없을 때만 사용자를 docker 그룹에 추가하고 다시 로그인한다.

```bash
sudo usermod -aG docker "$USER"
```
