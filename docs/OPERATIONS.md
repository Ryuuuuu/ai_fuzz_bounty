# 운영과 복구

작업 상태는 `data/runs/<job-id>/state.json`과 `artifacts/fuzz-progress.json`에 원자적으로
기록된다. 각 libFuzzer 체크포인트는 고유 세션 ID를 가지므로 상태 저장 중 호스트가
중단돼도 같은 세션 시간을 두 번 합산하지 않는다. 재시작할 때 남아 있는 작업 컨테이너는
이름과 라벨로 정리한 뒤 남은 예산만 실행한다.

각 실행은 호스트의 `corpus/<fuzz-target>/`를 컨테이너에 마운트하고 같은 경로를
`CORPUS_DIR`로 전달한다. 로그에서 체크포인트마다 corpus가 seed 개수로 되돌아가거나
`rm: cannot remove ..._corpus`가 반복되면 장기 실행을 중단하고 corpus 연속성을 먼저
점검한다. `fuzz-progress.json`의 corpus 수는 호스트 디렉터리의 실제 파일 수와 같아야 한다.

```bash
fuzz-pipeline migrate --dry-run
fuzz-pipeline migrate
fuzz-pipeline dashboard
fuzz-pipeline dashboard --watch
fuzz-pipeline housekeep
fuzz-pipeline worker --max-jobs 0
fuzz-pipeline agent
```

`doctor`는 현재 환경에서 감지한 CPU, 사용 가능 메모리, 동시 작업 수, 작업별 worker와
메모리를 표시한다. 자동 계산은 WSL 여부에 의존하지 않으며 일반 Ubuntu, VM과 cgroup으로
제한된 실행 환경에서도 동작한다. `resource_cpu_reserve`,
`resource_memory_reserve_mb`, `max_parallel_jobs`, `parallel_workers`를 설정하면 자동
계산의 상한과 호스트 여유분을 조정할 수 있다.

장기 운영에서는 `worker` 대신 `agent`를 사용한다. 중앙 에이전트는 별도 잠금으로
중복 실행을 막고, 종료 신호를 받으면 상태 파일에 기록된 활성 컨테이너를 중지한다.
다시 시작하면 기존 체크포인트에서 남은 시간만 이어서 실행한다. 30분 간격 상태 로그와
Telegram 전달 내역은 각각 `data/central-agent/progress.jsonl`과
`data/central-agent/notifications.jsonl`에 기록된다. 비밀값이나 crash 원본 바이트는
이 로그에 쓰지 않는다.

`housekeep`은 오래된 로그와 corpus를 설정된 파일 수·용량까지 줄이고 완료 작업의 임시
실행 복사본을 삭제한다. `artifacts`, `crashes`, `validation`, `poc`의 증거는 삭제하지
않는다. 작업 전체가 `job_disk_limit_mb`를 넘으면 `resource_limit_required`로 멈춘다.
프로세스가 사라진 `fts-*` Docker 컨테이너도 라벨을 확인한 뒤 정리한다.

`dashboard --json`은 자동화가 읽을 수 있는 상태를 출력한다. 일반 화면에는 작업 단계,
24시간 예산 진행률, 남은 시간, 처리량, crash 수, 검증 상태와 디스크 사용량이 표시된다.

실패 횟수는 작업 상태의 `attempts.worker_failures`에 남는다. 같은 작업이
`max_stage_failures`회 실패하면 자동 재시도를 중단하고 `manual_review`로 전환한다.
