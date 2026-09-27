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
중복 실행을 막고, 종료 신호를 받으면 worker에 정상 중지를 전달한 뒤 상태 파일에 기록된
활성 컨테이너를 중지한다. 정상 중지는 실패 횟수에 포함하지 않고 `interrupted`로 남긴다.
다시 시작하면 기존 체크포인트에서 남은 시간만 이어서 실행한다. 30분 간격 상태 로그와
Telegram 전달 내역은 각각 `data/central-agent/progress.jsonl`과
`data/central-agent/notifications.jsonl`에 기록된다. AI가 같은 문제를 다르게 표현해도
작업 ID와 문제 종류가 같으면 하나의 활성 경고로 묶고, 상태가 복구되거나 문제 종류가
바뀔 때만 다시 알린다. AI 판정 문구가 바뀌어도 `health_alert_cooldown_seconds` 동안 같은
등급의 AI 상태 경고를 다시 보내지 않는다. 누적 완료·실패 통계는 이력으로만 전달하여
현재 실행 장애로 판정하지 않는다. 기본 건강 판정은 독립 Codex 실행으로 처리해 오래된
대화와 토큰이 누적되지 않는다. Telegram의 일시적인 네트워크 오류는 지수 백오프로
재시도한다. 비밀값이나 crash 원본 바이트는 이 로그에 쓰지 않는다.

`housekeep`은 오래된 로그와 corpus를 설정된 파일 수·용량까지 줄이고 완료 작업의 임시
실행·빌드 복사본(`runtime-out`, `native-work`, `native-out`, `build-output`,
`build-source`, `source`)을 삭제한다. `artifacts`, `crashes`, `validation`, `poc`, 로그와
corpus의 증거는 삭제하지 않는다. 작업 전체가 `job_disk_limit_mb`를 넘으면
`resource_limit_required`로 멈춘다.
프로세스가 사라진 `fts-*` Docker 컨테이너도 라벨을 확인한 뒤 정리한다.

같은 저장소에서 `repository_failure_threshold`번 연속으로 빌드·통합 실패가 끝나면
`repository_failure_cooldown_hours` 동안 새 커밋을 큐에 넣지 않는다. 이미 큐에 있는
미시작 작업도 `skipped_repository_cooldown`으로 완료하여 다음 저장소를 탐색한다. 성공적으로 예산을 소진했거나 저수익으로 종료한 저장소도 `repository_success_cooldown_hours` 동안 GitHub 상세 조회 전부터 제외하여 동일 코드 반복과 API 소비를 막는다.

`low_yield_rotation_enabled`가 켜져 있으면 최소 2시간 관찰 뒤 `low_yield_min_coverage_edges`보다 얕으며 edge와 feature 증가가 모두 기준보다 작은 작업을 종료한다. 도달 범위가 충분해도 edge와 feature가 6시간 동안 함께 늘지 않으면 조기 전환한다. 판정 근거는 `artifacts/campaign-yield.json`에 남고 중앙 에이전트가 Telegram으로 알린다.

`dashboard --json`은 자동화가 읽을 수 있는 상태를 출력한다. 일반 화면에는 작업 단계,
24시간 예산 진행률, 남은 시간, 처리량, crash 수, 검증 상태와 디스크 사용량이 표시된다.

퍼징 실행 로그는 세션 ID가 포함된 별도 파일에 기록해 이전 세션의 sanitizer/OOM 문구가
현재 판정에 섞이지 않게 한다. 실패 횟수는 작업 상태의 `attempts.worker_failures`에 남는다.
실패하면 `recovery_pending`으로 전환하여 동일 단계를 즉시 반복하지 않는다. 중앙 AI가
허용된 조치 중 재시도 또는 통합 재구축을 선택하며, 통합 재구축 때 실패한 하네스와 기존
산출물은 `artifacts/history/`에 보존된다. 기본 두 번의 자동 복구로 해결되지 않으면
`skipped_after_recovery`로 완료하고 다음 보상 대상으로 진행한다. 정책 재검증 실패,
검증 결과가 불완전한 crash처럼 자동 처리하면 안 되는 상태는 기존 수동 검토 게이트를
유지한다.
