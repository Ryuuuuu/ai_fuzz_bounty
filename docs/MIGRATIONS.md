# 업데이트와 상태 마이그레이션

새 버전을 설치하기 전에 중앙 agent 또는 worker를 종료하고 현재 저장소와 `data/runs`를
백업한다.

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
fuzz-pipeline migrate --dry-run
fuzz-pipeline migrate
python -m unittest discover -s tests -v
fuzz-pipeline doctor
```

마이그레이션은 각 작업의 현재 스키마를 검사하고 필요한 파일만 원자적으로 교체한다.
최초 변경 때 기존 상태는 `state.v<version>.json`으로 한 번 보존된다. 이미 최신인 작업에
다시 실행해도 내용은 바뀌지 않는다. 현재 패키지보다 새로운 상태 스키마는 자동으로
변경하지 않고 실패 목록에 기록한다.
