# 중앙 AI 에이전트

`fuzz-pipeline agent`는 대상 탐색부터 병렬 퍼징, 상태 판정, 결과 검토까지 한 프로세스에서
조정한다. 실제 퍼징과 재현은 기존 격리 Docker 경로를 사용하며, AI는 보상 정책을 승인하거나
결과를 외부에 제출할 수 없다.

## 실행 흐름

1. 실행 가능한 작업이 있으면 즉시 시작한다. 큐가 비었거나 앞 작업 묶음이 끝난 뒤 탐색
   주기가 지났으면 GitHub 후보를 갱신하고 verified export를 다시 계획한다.
2. CPU affinity, cgroup v1/v2, `/proc`와 Docker 제한으로 안전한 자원 선택지를 만든다.
   같은 Daybreak Blue high 모델이 선택지 하나를 고르며, 제안값은 결정적 안전 상한으로
   다시 제한한다.
3. 선택한 개수의 독립 작업을 병렬 실행한다. 빌드와 AI 품질 검토는 공유 잠금으로 순차
   실행된다.
4. 기본 1,800초마다 전체 상태와 이전 측정 대비 진행량을 JSONL에 기록한다. AI에는 압축된
   지표, 상태와 오류만 전달한다. 상태 감시용 Codex 세션은 24회까지 재사용해 반복되는
   지시문과 이전 상태의 캐시를 활용한 뒤 새 세션으로 교체한다.
5. 새 crash, 재현된 triage 그룹, PoC 또는 검증 보고서를 발견하면 Telegram으로 알린다.
   같은 파일 내용은 SHA-256으로 중복 알림을 막는다.
6. 현재 병렬 묶음이 끝나면 다음 대상을 시작하기 전에 종료 검토를 실행한다. 남아 있는
   검증된 coverage gap에 대해서만 후속 하네스를 한 번 생성하고 10분 probe와 품질 게이트를
   다시 수행할 수 있다.

## Telegram 설정

BotFather에서 만든 bot token과 알림을 받을 chat ID를 현재 셸의 환경변수에 둔다.

```bash
export FUZZ_TELEGRAM_BOT_TOKEN='123456:...'
export FUZZ_TELEGRAM_CHAT_ID='-100...'
fuzz-pipeline agent --test-telegram
```

설정 파일에는 비밀값 대신 환경변수 이름만 들어간다. Telegram 값, GitHub token과 API
키는 중앙 Codex 프로세스 환경에서 제거된다. Telegram이 설정되지 않아도 퍼징과 로컬
로그는 계속 동작하며, 아직 전달되지 않은 새 결과는 상태에 남아 다음 실행에서 재시도한다.

## 실행과 점검

```bash
# 상태 검토 한 번만 수행
fuzz-pipeline agent --once --no-discovery

# 큐가 빌 때까지만 한 번 운영 점검
fuzz-pipeline agent --max-batches 1 --exit-when-idle

# 지속 운영
fuzz-pipeline agent
```

사용자 systemd를 쓰는 Ubuntu나 WSL에서는 저장소 위치를 자동 반영하는 설치 스크립트를
사용할 수 있다. 스크립트는 서비스를 바로 시작하지 않으며, 권한이 `600`인 사용자 설정
파일을 만든다.

```bash
./scripts/install_central_agent_service.sh
nano ~/.config/ai-fuzz-bounty/agent.env
systemctl --user enable --now fuzz-central-agent.service
systemctl --user status fuzz-central-agent.service
```

중지와 로그 확인은 다음과 같다.

```bash
systemctl --user stop fuzz-central-agent.service
journalctl --user -u fuzz-central-agent.service -f
```

기본 파일은 다음과 같다.

- `data/central-agent/state.json`: 재시작 상태, 전달된 결과 해시, 최근 자원 결정
- `data/central-agent/progress.jsonl`: 30분 상태 스냅샷과 AI 판정
- `data/central-agent/notifications.jsonl`: Telegram 성공·실패 기록
- `data/central-agent/codex-sessions.json`: 재사용 중인 상태 감시 세션 ID와 교체 횟수
- `data/central-agent/decisions/`: 자원, 상태 및 대상 종료 검토 원문
- `data/runs/<job-id>/artifacts/central-cycle-review.json`: 대상별 종료 판단
- `data/runs/<job-id>/artifacts/central-improvement.json`: 후속 하네스 적용 결과

`monitor_interval_seconds`, 대상 탐색 주기와 개선 probe 시간은 `config.toml`의 `[agent]`
섹션에서 조정한다. 운영 중 별도의 `fuzz-pipeline worker`를 함께 실행하지 않는다.
