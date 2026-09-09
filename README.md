# Fuzz Target Scout

Linux에서 자동 퍼징하기 편한 공개 저장소를 찾고, 금전 보상 정책이 확인된
후보만 격리된 AI 퍼징 파이프라인으로 넘기는 범용 시스템입니다. 특정 제품에
종속되지 않습니다. 기존 OSS-Fuzz 통합이 있는 C/C++ 프로젝트를 우선 처리하고,
미등록 프로젝트는 CMake, Meson, Autotools, Cargo를 감지해 작업별 OSS-Fuzz 정의와
초기 하네스를 생성합니다.

## 판정 흐름

1. GitHub Repository Search에서 최근 유지보수되는 C, C++, Rust, Go 저장소를 찾습니다.
2. 각 저장소의 SECURITY.md를 먼저 읽습니다.
3. 저장소 정책이 유료 바운티를 명시하거나, 날짜가 기록된 검증 카탈로그와
   정확히 일치할 때만 verified로 판정합니다.
4. verified와 conditional 후보에 대해서만 파일 트리와 README를 읽어
   빌드 방식, Linux 지원, 테스트, 기존 fuzz harness, 저장소 크기를 평가합니다.
5. 정적 점수를 통과한 verified 후보 중 상위 몇 개만 AI가 재평가합니다.
6. 기본 export는 verified만 JSONL로 내보냅니다. needs_review, rejected,
   초대제인 conditional은 자동 파이프라인에서 제외됩니다.
7. 작업 생성 시 고정된 OSS-Fuzz 프로젝트 인덱스와 대조해 등록된 후보를 먼저 큐에
   넣고, 미등록 후보는 지원 빌드 파일 신호를 확인한 뒤 범용 통합 생성 경로로 넘깁니다.

AI는 보상 정책을 승인할 수 없습니다. 정책 판정은 현재 SECURITY.md의 명시적
문구와 catalog.json에 기록된 공식 정책 근거만 사용합니다. 카탈로그 항목은
기본 45일 후 자동으로 needs_review 상태가 됩니다.

## Ubuntu 및 WSL2 설치

    git clone https://github.com/Ryuuuuu/ai_fuzz_bounty.git
    cd ai_fuzz_bounty
    ./scripts/bootstrap_ubuntu.sh
    source .venv/bin/activate

지원 기준은 Ubuntu 24.04 이상 또는 Python 3.11 이상이 설치된 Ubuntu/WSL2,
Git, Docker Engine, 로그인된 Codex CLI입니다. 설치 경로나 사용자 이름은
가정하지 않습니다. `parallel_workers`, `max_parallel_jobs`와 컨테이너 메모리를
0으로 두면 실행 시점의 CPU affinity, cgroup v1/v2, `/proc/meminfo`와 Docker
daemon 제한을 조합해 자동 계산합니다.

GitHub의 비인증 API 제한은 반복 탐색에 부족하므로 읽기 전용 토큰을 환경변수로
설정하는 것을 권장합니다. 토큰을 설정 파일이나 저장소에 기록하지 마세요.

    export GITHUB_TOKEN='...'
    codex login
    fts doctor
    fts ai-check

AI 재평가는 Linux 환경에 설치되고 로그인된 Codex CLI를 비대화식으로 호출합니다.
별도 OPENAI_API_KEY는 필요하지 않습니다. 기본 모델은
gpt-daybreak-blue-latest, reasoning effort는 high입니다. Daybreak 프로그램
접근 권한이 계정에 별도로 준비되어 있어야 합니다.

## 사용

먼저 포함된 정책 카탈로그 10개로 전체 흐름을 확인할 수 있습니다.

    fts scan --catalog-only --no-ai
    fts list
    fts export

GitHub를 검색하고 상위 후보만 AI로 재평가하려면:

    fts scan --limit 40
    fts list --all
    fts export --minimum-score 55

반복 실행:

    fts daemon --limit 40 --interval-seconds 21600

실제 운영에서는 systemd timer나 별도 작업 관리자가 fts scan을
주기적으로 실행하는 구성이 더 관리하기 쉽습니다. daemon은 간단한 장시간
실행용입니다.

출력 파일 data/verified-candidates.jsonl의 각 줄에는 저장소, 확인한 commit,
정책 URL, 점수, 재현 난이도, 추천 진입 형태가 들어갑니다. 후속 AI-Fuzz
파이프라인은 이 파일에서 한 줄씩 가져가 24시간 작업 단위를 만들 수 있습니다.

## 다음 AI-Fuzz 파이프라인

정책이 확인된 C/C++ 후보를 고정된 24시간 작업 주문으로 만들 수 있습니다.

    fuzz-pipeline doctor
    fuzz-pipeline plan --limit 1
    fuzz-pipeline list
    fuzz-pipeline prepare --job-id <job-id>
    fuzz-pipeline integrate --job-id <job-id>
    fuzz-pipeline build --job-id <job-id>
    fuzz-pipeline smoke --job-id <job-id>
    fuzz-pipeline probe --job-id <job-id>
    fuzz-pipeline quartet --job-id <job-id>
    fuzz-pipeline analyze --job-id <job-id>
    # analyze가 새 하네스를 요구할 때만 실행
    fuzz-pipeline generate --job-id <job-id>
    fuzz-pipeline run --job-id <job-id>
    # 4시간 정체 뒤 worker가 자동 실행하며, 기록된 정체 작업에는 수동 실행도 가능
    fuzz-pipeline afl-cmplog --job-id <job-id>
    # run이 끝난 뒤 자동 worker가 수행하며, 수동 실행도 가능
    fuzz-pipeline triage --job-id <job-id>
    fuzz-pipeline validate --job-id <job-id>

준비된 작업을 오래된 순서대로 24시간 실행하고 다음 작업으로 넘기려면:

    fuzz-pipeline worker --max-jobs 0

현재 진행률, corpus, crash와 정체 상태 확인:

    fuzz-pipeline status --job-id <job-id>
    fuzz-pipeline dashboard --watch
    fuzz-pipeline housekeep

`--max-jobs 0`은 실행 가능한 큐가 빌 때까지 처리하며 기본값이다. 감지된 자원 범위에서
여러 작업의 장기 퍼징을 동시에 실행한다. 준비·빌드·Codex 검토는 공유 산출물과 토큰을
보호하기 위해 한 번에 하나씩 수행하고, 품질 게이트를 통과한 기존 및 AI 생성 하네스는
같은 병렬 자원 스케줄러에서 실행한다. 빌드와 검증까지만 미리 진행하려면
`--setup-only`를 사용한다. 동시에 두 스케줄러가 실행되지 않도록 잠금 파일을 사용한다.
크래시가 생기면 worker가 입력 최소화, 격리 환경 3회 재현, sanitizer
스택 지문 중복 제거를 수행한다. 재현된 그룹만 별도 Codex 검증 에이전트가 로컬 전용
PoC, 트리거 경로, 영향도 근거와 사람 검토용 보고서 초안으로 정리한다.
실행 세션별 완료 시간을 기록하므로 worker나 호스트가 중단돼도 남은 퍼징 예산만
재개한다. 결과를 외부 버그바운티 서비스에 자동 제출하지 않는다.

한 프로젝트에서 여러 퍼징 바이너리가 빌드되면 스모크 검사, 짧은 ASan 프로브,
Quartet 검토를 최대 `max_fuzz_target_attempts`개까지 순서대로 수행한다. 실패한 하네스의
증거는 `artifacts/target-history/`에 보존하고 다음 하네스를 시도한다. 프로브 중 sanitizer
발견이 생기면 정상 결과로 숨기지 않고 장기 실행을 차단한다. 긴 하네스의 AI 입력은
원래 줄 번호를 유지한 핵심 구간 700줄 이하로 제한한다.

`fuzz-pipeline doctor`가 Docker socket 권한 오류를 표시하면 현재 사용자를 docker
그룹에 추가한 뒤 다시 로그인해야 합니다. 정확한 절차는 파이프라인 문서에 있습니다.

작업 주문은 `data/runs/<job-id>/job.json`에 생성됩니다. OSS-Fuzz와
OSS-Fuzz-Gen을 기본 경로로 사용하고 QuartetFuzz의 P1-P4를 품질 게이트로
적용합니다. AFL++ CmpLog는 4시간 동안 corpus가 늘지 않을 때 한 번 실행하고 새 입력을
기존 corpus로 되돌립니다. 새 입력이 없으면 소스 문자열 dictionary를 만들고, 다시
정체되면 이미 측정한 미도달 후보로 새 하네스를 생성합니다. probe나 본 퍼징 체크포인트의 crash는 남은 시간을 소모하지
않고 즉시 triage로 넘깁니다. VistaFuzz는 OpenCV-Python 전용 연구 아티팩트이므로
일반 후보에 연결하지 않습니다. `fuzz-pipeline vistafuzz`로 고정 버전과 API 자료를
점검할 수 있고, 명시적으로 활성화한 경우에만 별도 스모크를 실행합니다. 전체 방법론과 단계별 산출물은
[`docs/FUZZ_PIPELINE.md`](docs/FUZZ_PIPELINE.md)에 정리되어 있습니다.

설치 절차는 [`docs/INSTALL.md`](docs/INSTALL.md), 운영·복구는
[`docs/OPERATIONS.md`](docs/OPERATIONS.md), 버전 업데이트는
[`docs/MIGRATIONS.md`](docs/MIGRATIONS.md)를 따릅니다.

OSS-Fuzz-Gen의 `--ai-binary`에는 로컬 Codex 어댑터를 지정합니다.

    --ai-binary "$(command -v oss-fuzz-gen-codex)"

초대제 후보까지 의도적으로 포함하려면 다음 옵션을 사용합니다.

    fts export --include-conditional

## 토큰 및 API 호출 절감

- SECURITY.md가 없거나 유료 범위가 확인되지 않으면 코드 트리를 읽지 않습니다.
- AI는 verified이면서 정적 점수가 기준 이상인 후보만 호출합니다.
- 한 번의 scan에서 상위 후보 최대 5개를 하나의 Codex 호출로 묶습니다.
- AI에는 README나 정책 원문 대신 계산된 신호와 관련 경로 최대 40개만 보냅니다.
- 저장소 commit, 증거 해시, 모델, 프롬프트 버전이 같으면 SQLite 캐시를 사용합니다.
- codex exec를 빈 임시 작업공간의 read-only, ephemeral 모드로 실행하고
  JSON Schema 출력을 받아 고정 컨텍스트 비용과 파싱 실패를 줄입니다.

이 값들은 config.toml의 ai, github, scoring 섹션에서 조정할 수 있습니다.

## 테스트

    python -m unittest discover -s tests -v
