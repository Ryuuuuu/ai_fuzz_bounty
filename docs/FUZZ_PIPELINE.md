# AI-Fuzz 파이프라인 V1

## 목표와 범위

탐색기가 만든 `verified-candidates.jsonl`을 받아 Linux C/C++ 프로젝트 하나를
고정 커밋에서 준비하고, 검증된 하네스로 24시간 퍼징한 뒤 사람이 판단할 수 있는
재현 자료를 남긴다. V1은 공개 버그바운티 범위가 현재도 확인되는 후보만 받으며,
자동 제보나 익스플로잇 생성은 하지 않는다.

## 도구 적용 방식

| 도구 | 파이프라인에서 맡는 역할 | 적용 시점 |
|---|---|---|
| [OSS-Fuzz](https://github.com/google/oss-fuzz) | Linux 컨테이너 빌드, libFuzzer, ASan/UBSan, 커버리지와 크래시 최소화 | 모든 C/C++ 작업 |
| [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) | 진입점 후보와 하네스 생성, 빌드 오류 피드백 수정, 기존 하네스 대비 커버리지 평가 | 하네스가 없거나 범위 확장이 필요할 때 |
| [QuartetFuzz](https://github.com/OwenSanzas/QuartetFuzz) | P1 논리 정확성, P2 API 규약, P3 공개 보안 경계, P4 진입점 적절성 검사 | 하네스 빌드 전후의 필수 게이트 |
| [Fuzz Introspector](https://github.com/ossf/fuzz-introspector) | 도달 함수, 미도달 코드, 하네스별 커버리지 차이 측정 | 진입점 선택과 4시간 정체 시점 |
| [AFL++](https://github.com/AFLplusplus/AFLplusplus) | CmpLog로 매직 값과 복잡한 비교를 넘기는 보조 실행 | 파일/CLI 입력이며 커버리지가 4시간 정체할 때만 |
| [VistaFuzz](https://github.com/beanduan22/VistaFuzz) | OpenCV-Python 전용 문서 제약 퍼징 아티팩트의 고정 버전 점검과 별도 스모크 | 일반 후보와 분리된 연구 보조 경로 |

각 버전은 `toolchain.lock.json`의 커밋으로 고정한다. OSS-Fuzz-Gen과
QuartetFuzz가 기본적으로 API 모델을 기대하는 부분은 로컬 `codex exec` 어댑터로
교체한다. Codex에는 저장소 원문 전체를 매번 보내지 않고, 함수 시그니처·관련 타입,
테스트 사용 예와 직전 빌드 오류만 제공한다.

OSS-Fuzz-Gen에는 설치 후 생성되는 `oss-fuzz-gen-codex` 실행 파일을
`--ai-binary`로 전달한다. 이 어댑터는 OSS-Fuzz-Gen의 인자와 `.rawoutput` 계약을
그대로 구현하며 ChatGPT로 로그인된 로컬 Codex를 사용한다. 기본 sample cap은 1이다.

VistaFuzz는 일반 Python 라이브러리용 도구가 아니다. 공식 구현이 자체 OpenCV 환경을
빌드하므로 그 결과를 임의의 후보 커밋에 대한 버그바운티 증거로 사용하지 않는다.
`fuzz-pipeline vistafuzz`는 고정 커밋과 API 데이터 해시를 점검하고,
`vistafuzz_enabled=true`일 때만 `--smoke-seconds`로 격리된 연구 스모크를 실행한다.

## 작업 상태

```text
queued
  → policy_recheck
  → source_checkout
  → integration
  → smoke
  → probe
  → quartet_gate
  → coverage_analysis
  → fuzzing_asan_24h
      ↳ corpus 4시간 정체 시 afl_cmplog 1회 → fuzzing_asan_24h
  → triage
  → validation
  → ready_for_human | exhausted | failed
```

1. **policy_recheck**: 같은 저장소와 범위가 여전히 금전 보상 대상인지 다시 확인한다.
2. **source_checkout**: 작업 주문의 커밋만 체크아웃하고 실제 SHA가 같은지 확인한다.
3. **integration**: 기존 하네스를 우선 재사용한다. 없으면 테스트 코드를 우선 자료로
   OSS-Fuzz-Gen 방식의 하네스를 최대 3회 생성·수정한다.
4. **smoke / probe**: 빌드된 하네스를 짧게 실행해 실제 동작과 sanitizer 발견을
   확인한다. 여러 하네스가 있으면 최대 `max_fuzz_target_attempts`개까지 순서대로
   평가하고 이전 증거를 `artifacts/target-history/`에 보존한다.
5. **quartet_gate**: P1–P4와 입력 도달 여부를 검사한다. 하네스 자체 오류나 probe의
   sanitizer 발견은 여기서 장기 실행을 차단한다. 700줄을 넘는 하네스는 원문 줄 번호를
   유지한 핵심 구간만 AI에 전달한다. 하네스가 통과하고 probe 발견이 남아 있으면
   coverage 분석과 장기 실행을 생략하고 즉시 triage한다.
6. **coverage_analysis**: 60초 probe 결과와 공개 Fuzz Introspector 후보를 고정
   커밋의 파일에 대조한다. 직접 바이트 입력이 가능한 후보가 있을 때만 시그니처와
   수치를 한 번의 Codex 호출에 보내 기존 하네스 실행, 확장, 새 하네스 생성 중
   하나를 고른다. 후보가 모두 상태 의존적이면 규칙 기반 게이트가 호출을 생략한다.
7. **fuzzing**: ASan/libFuzzer를 자동 계산된 worker 수로 총 86,400초 실행한다.
   기본 한 시간 체크포인트마다 corpus 성장과 실행량을 기록하고, 4시간 동안 corpus가
   늘지 않으면 고정 OSS-Fuzz가 제공하는 AFL++ CmpLog를 기본 3,600초 한 번 실행한다.
   실행 컨테이너에는 마운트한 corpus 경로를 `CORPUS_DIR`로 명시한다. OSS-Fuzz의
   `run_fuzzer`가 체크포인트마다 기본 corpus를 초기화하지 않으므로 앞 세션의 입력을
   다음 세션과 AFL++ 보조 실행이 그대로 이어받는다.
   AFL queue는 SHA-256으로 중복 제거해 libFuzzer corpus로 환류한다. AFL에서 나온
   crash는 원래 ASan/libFuzzer 빌드로 triage한다. 보조 빌드나 실행이 실패하면 오류
   산출물을 남기고 libFuzzer 실행을 계속한다. 본 퍼징 체크포인트에서 crash가 나오면
   남은 예산을 소모하지 않고 즉시 triage한다.
8. **triage**: 입력 최소화, 깨끗한 컨테이너에서 3/3 재현, 심볼화, 스택 기준 중복 제거,
   UBSan 교차 확인과 검증 인계 자료 생성을 거친다.
9. **validation**: 별도 Codex 에이전트가 검증된 그룹만 읽어 로컬 전용 PoC, 트리거
   경로, 영향 근거와 사람 검토용 보고서 초안을 만든다. 외부 제출은 하지 않는다.

준비는 최대 90분, 마지막 triage는 최대 60분이다. 준비 실패 시간을 24시간 퍼징
예산으로 계산하지 않는다.

## AI를 쓰는 위치

AI가 하는 일은 다섯 가지로 제한한다.

1. 테스트와 공개 API에서 진입점을 순위화한다.
2. 하네스·dictionary·작은 seed 후보를 생성한다.
3. 압축한 컴파일 오류를 보고 최대 3회 수정한다.
4. Fuzz Introspector 결과에서 다음 하네스가 노릴 미도달 경로를 설명한다.
5. 재현된 크래시의 호출 흐름과 보고서 초안을 만든다.

정책 승인, 크래시 진위, 중복 여부의 최종 판단, 보안 영향과 제보는 AI에 맡기지 않는다.
빌드, sanitizer, 커버리지, 반복 재현 결과가 AI 판단보다 우선한다.

## 토큰과 계산량 절감

- 기존 하네스가 있으면 새로 생성하지 않고 커버리지 차이만 분석한다.
- 함수 전체가 아니라 시그니처, 직접 관련 타입, 테스트 사용 예만 보낸다.
- 같은 커밋·하네스·오류 해시의 응답은 재사용한다.
- 빌드 수정은 최대 3회에서 중단한다.
- 정상 퍼징 루프에는 AI를 호출하지 않는다.
- 커버리지가 4시간 정체하거나 크래시가 생겼을 때만 다시 호출한다.
- 여러 진입점의 정적 검토는 한 번의 구조화 출력 호출로 묶는다.

## 격리와 산출물

의존성 다운로드가 끝난 퍼징 컨테이너는 네트워크 없이 실행한다. 소스는 읽기 전용,
corpus·crash·log 디렉터리만 쓰기 가능하게 마운트한다. GitHub/OpenAI 관련 환경
변수는 Codex와 대상 컨테이너에 전달하지 않는다.

각 작업은 `data/runs/<job-id>/` 아래에 다음을 남긴다.

```text
job.json          고정 입력, 정책 증거, 도구 커밋, 예산
state.json        현재 단계와 시도 횟수
integration/      Dockerfile, build.sh, harness
corpus/           누적 corpus
crashes/          원본·최소화 입력과 재현 메타데이터
artifacts/        coverage, symbolized stack, 중복 그룹, 사람 검토 보고서
logs/             빌드와 실행 로그
```

## 현재 구현된 경계

`fuzz-pipeline plan`은 정책·커밋·언어 게이트를 다시 검사하고 위 계약의 작업 폴더를
멱등적으로 만든다. 계획 시점에 `oss-fuzz-support.json`을 사용해 고정 OSS-Fuzz
프로젝트 정의가 있는 후보를 먼저 배치한다. 정의가 없는 후보는
`allow_generic_integrations=true`일 때 CMake, Meson, Autotools, Cargo 템플릿과
Codex/OSS-Fuzz-Gen 초기 하네스로 작업별 비공개 프로젝트 정의를 만든다. 탐색 단계에서
지원 빌드 파일 신호가 없는 후보는 checkout 전에 제외한다.
인덱스는 `scripts/build_oss_fuzz_index.py`로 같은 도구 커밋에서 재생성하며, 커밋이
다르면 계획을 거부한다. `fuzz-pipeline prepare --job-id <id>`는 현재 정책을 다시
확인하고, 고정 커밋만 checkout하고, 작업 주문에 기록된 공식 도구 커밋을 동기화한
뒤 `integration` 단계에서 멈춘다. 이 준비 단계는 내려받은 코드를 실행하지 않는다.
기존 OSS-Fuzz 프로젝트가 있으면 다음 단계도 실행할 수 있다.

```bash
fuzz-pipeline integrate --job-id <id>
fuzz-pipeline build --job-id <id>
fuzz-pipeline smoke --job-id <id>
fuzz-pipeline probe --job-id <id>
fuzz-pipeline quartet --job-id <id>
fuzz-pipeline analyze --job-id <id>
# analyze 결과가 extend_existing 또는 generate_new_harness일 때만
fuzz-pipeline generate --job-id <id>
fuzz-pipeline run --job-id <id>
# 기록된 coverage 정체 작업에만 실행 가능하며 worker는 자동 호출한다.
fuzz-pipeline afl-cmplog --job-id <id>
fuzz-pipeline triage --job-id <id>
fuzz-pipeline validate --job-id <id>
fuzz-pipeline dashboard --watch
fuzz-pipeline housekeep
```

원본 checkout은 증거용으로 깨끗하게 유지하고 별도 Git worktree에서만 빌드한다.
OSS-Fuzz 저장소와 프로젝트 정의도 작업마다 별도 worktree로 고정한다. 따라서 서로
다른 프로그램의 Dockerfile, 하네스 수정과 `build/out`이 겹치지 않는다.
빌드 이미지 ID, 생성된 fuzzer 목록과 smoke 대상은 artifacts에 기록한다. 생성 통합은
지원하는 빌드 시스템을 먼저 확인하고, 공개 함수 시그니처와 제한된 소스 문맥만 AI에
전달한다. 생성된 하네스는 프로세스·네트워크 호출을 정적으로 거부하고 공식 OSS-Fuzz
빌드와 이후의 probe·Quartet 게이트를 동일하게 통과해야 한다.
범용 CMake 통합 자체는 `python scripts/verify_generic_integration.py`로 작은 정적
라이브러리를 공식 OSS-Fuzz helper에서 실제 빌드해 확인할 수 있다.
`probe`는 격리 구성과 처리량을 60초 확인한다. `quartet`은 고정된
QuartetFuzz 매뉴얼의 P1–P4 기준으로 하네스를 한 번 구조화 검토하고 기존 ASan 빌드,
smoke와 probe 결과를 함께 기록한다. 빌더 이미지에 GDB가 없으면 P4 함수 도달은
중간 신뢰도로 명시하며, 디버거로 확인했다고 기록하지 않는다. `analyze`는 공개 Introspector
자료가 고정 커밋에 실제 존재하는지 확인하고, 직접 바이트 입력 경계가 있는 경우에만
최대 10개의 압축된 후보를 로컬 Codex에 한 번 전달한다. 분석이 기존 하네스 실행을
승인해야만 `run`이 시작된다. `run`은
작업 주문의 86,400초를 임의로 줄이지 않고 실행한 뒤 `triage` 단계로 넘긴다.
실행 컨테이너에는 작업용 빌드 산출물 복사본만 쓰기 가능하게 마운트하며, 고정 소스와
원본 빌드 산출물은 수정하지 않는다.
각 ASan 빌드 결과는 작업별 `build-output/asan`에 복사하므로 다른 작업의 OSS-Fuzz
빌드가 공용 `build/out`을 덮어도 이미 준비된 작업의 실행 파일은 바뀌지 않는다.

`generate`는 분석이 기존 하네스 확장이나 새 하네스를 명시적으로 요구한 작업에서만
동작한다. 고정 OSS-Fuzz-Gen의 `--ai-binary`/`.rawoutput` 계약으로 로컬 Codex를 한 번
호출하고, 공식 OSS-Fuzz 빌드가 실패하면 압축된 오류만 넘겨 최대 3회 수정한다. 생성
코드는 증거용 checkout이 아니라 빌드 worktree의 기존 하네스 위치에만 적용한다.
성공 후 smoke, probe, Quartet, coverage 분석을 새 하네스에 다시 수행한다.

`fuzz-pipeline worker --max-jobs 0`은 생성 시간이 오래된 작업부터 위 상태 전이를
실행한다. 실행 시 CPU affinity, cgroup v1/v2, `/proc/meminfo`와 Docker daemon의
CPU·메모리 제한을 각 작업 묶음 시작 시 측정하고 가장 작은 유효 제한을 사용한다. CPU 1개와 메모리 1GB를
기본 여유분으로 남긴 뒤 동시 작업 수, 작업별 libFuzzer worker 수, 컨테이너 메모리와
worker RSS 제한을 함께 계산한다. 각 실행의 측정값은 `artifacts/resource-plan.json`에
남긴다.

한 coordinator만 잠금을 획득하지만, 승인된 장기 퍼징 작업은 계산된 개수만큼 별도
Docker 컨테이너에서 동시에 실행한다. 준비·빌드·probe·Quartet·coverage 검토와 하네스
생성은 공유 도구와 빌드 산출물 충돌을 피하도록 직렬화한다. OSS-Fuzz-Gen이나 정체 대응
Codex 단계에서 생성된 하네스도 동일한 자원 할당을 받아 기존 하네스 작업과 병렬 실행된다.
각 작업의 24시간 예산이 끝나 `triage_pending`이 되면 다음 작업을 선택한다.
하네스 생성은 작업당 최대 두 사이클로 제한하며, 그 이상은 사람 검토 대상으로 남긴다.
전체 퍼징 직전 버그바운티 정책을 다시 확인한다.
`fuzz-progress.json`에 정상 완료 및 중단 세션을 누적한다. 재부팅 뒤 `running` 또는
`interrupted` 작업을 다시 선택하고 이미 완료한 실행 시간을 제외한 예산만 요청한다.
각 체크포인트는 고유 실행 ID로 결과와 진행률을 연결해 상태 기록 직전 중단에도 한 번만
합산한다. 기본 체크포인트는 3,600초이며 `fuzz_checkpoint_seconds`로 조정할 수 있다.
CmpLog 보조 실행은 `afl_cmplog_enabled`로 끌 수 있고 `afl_cmplog_seconds`로 실행 시간을
정한다. 빌드 산출물에는 OSS-Fuzz Dockerfile이 선언한 AFL++ 커밋, 실제 `afl-fuzz`와
대상 바이너리의 SHA-256, 프로젝트 builder 이미지 ID를 기록한다.

후속 검증 에이전트를 위해 각 `job.json`에는 `validation_handoff` 계약이 들어간다.
최소화 입력과 SHA-256, 심볼화 스택, 소스·도구 커밋, 깨끗한 환경의 3/3 재현 자료가
모두 있어야 넘길 수 있다. 후속 출력은 비무기화 PoC, 재현 순서, 트리거 조건,
근거 기반 영향도, 중복 조사 기록과 사람 검토용 보고서 초안이다.

`triage`는 ASan 결과를 최대 20개까지 읽고 원본 SHA-256을 기준으로 별도 검증 폴더를
만든다. 네트워크가 차단된 read-only 컨테이너에서 최소화를 시도한 뒤 같은 입력을
세 번 실행한다. 세 sanitizer 지문이 모두 같을 때만 검증 그룹으로 인정하며, 주소를
정규화한 스택 지문으로 중복 입력을 묶는다. 검증된 그룹은 별도 UBSan 빌드에서도 한 번
교차 실행한다. 검증된 그룹만 `validation-handoff.json`에
포함한다. 재현되지 않은 그룹은 sanitizer 미검출과 불안정한 지문을 구분해 이유를
기록한다. 다음 `validation` 단계의 Codex에는 입력 바이트나 전체 소스를 보내지 않고
지문, 프레임, 제한된 소스 구간, 크기와 고정 커밋만 한 번에 전달한다. 생성된 PoC는
네트워크가 없는 OSS-Fuzz 재현 컨테이너만 실행한다.

4시간 정체 뒤 AFL++에서도 새 corpus가 없으면 현재 고정 소스와 하네스의 문자열을
제한적으로 추출해 libFuzzer dictionary를 만든다. dictionary 적용 뒤 다시 정체되면
기존 coverage 분석에서 확인한 후보 하나를 선택해 OSS-Fuzz-Gen 빌드 수정 루프로
넘긴다.

운영 중에는 `dashboard`, `housekeep`, `migrate` 명령을 사용한다. 디스크 제한,
corpus·로그 정리, 고아 컨테이너 제거, 실패 횟수 제한과 상태 스키마 백업 절차는
`OPERATIONS.md`와 `MIGRATIONS.md`에 정리되어 있다.

Ubuntu 사용자가 Docker 소켓을 사용할 수 없으면 한 번만 다음을 실행하고 로그아웃한
뒤 다시 로그인한다.

```bash
sudo usermod -aG docker "$USER"
```

WSL2에서는 Windows 터미널에서 `wsl --shutdown` 후 다시 열어도 된다. 다시 로그인한
뒤 `docker info`와 `fuzz-pipeline doctor`가 성공해야 한다. Docker
소켓 권한을 모든 사용자에게 여는 방식은 사용하지 않는다.
