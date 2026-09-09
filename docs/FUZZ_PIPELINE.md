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
| [VistaFuzz](https://github.com/beanduan22/VistaFuzz) | 문서에서 타입·shape·인자 관계를 한 번 추출하고 유효한 Python API 입력 생성 | Python 경로를 나중에 활성화할 때만 |

각 버전은 `toolchain.lock.json`의 커밋으로 고정한다. OSS-Fuzz-Gen과
QuartetFuzz가 기본적으로 API 모델을 기대하는 부분은 로컬 `codex exec` 어댑터로
교체한다. Codex에는 저장소 원문 전체를 매번 보내지 않고, 함수 시그니처·관련 타입,
테스트 사용 예와 직전 빌드 오류만 제공한다.

OSS-Fuzz-Gen에는 설치 후 생성되는 `oss-fuzz-gen-codex` 실행 파일을
`--ai-binary`로 전달한다. 이 어댑터는 OSS-Fuzz-Gen의 인자와 `.rawoutput` 계약을
그대로 구현하며 ChatGPT로 로그인된 로컬 Codex를 사용한다. 기본 sample cap은 1이다.

VistaFuzz는 일반 C/C++ 파일 파서에 넣지 않는다. 문서 제약이 중요한 Python API일
때만 `pipeline.languages`에 `Python`을 추가해 별도 경로를 활성화한다.

## 작업 상태

```text
queued
  → policy_recheck
  → source_checkout
  → integration
  → quartet_gate
  → smoke
  → fuzzing_asan_24h
  → triage
  → ready_for_human | exhausted | failed
```

1. **policy_recheck**: 같은 저장소와 범위가 여전히 금전 보상 대상인지 다시 확인한다.
2. **source_checkout**: 작업 주문의 커밋만 체크아웃하고 실제 SHA가 같은지 확인한다.
3. **integration**: 기존 하네스를 우선 재사용한다. 없으면 테스트 코드를 우선 자료로
   OSS-Fuzz-Gen 방식의 하네스를 최대 3회 생성·수정한다.
4. **quartet_gate**: P1–P4와 입력 도달 여부를 검사한다. 하네스 자체 오류는 여기서
   탈락시킨다.
5. **smoke**: ASan 빌드로 5분 실행하고 같은 입력에서 결과가 결정적인지 확인한다.
6. **fuzzing**: ASan/libFuzzer를 기본 6개 worker로 86,400초 실행한다. 4시간 동안
   커버리지가 늘지 않고 입력 형태가 맞을 때만 AFL++ CmpLog를 추가한다.
7. **triage**: 입력 최소화, 깨끗한 컨테이너에서 3/3 재현, 심볼화, 스택 기준 중복 제거,
   UBSan 교차 확인을 거친다.

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
멱등적으로 만든다. 다음 구현 단위는 고정 커밋 checkout, 도구 동기화, OSS-Fuzz
외부 프로젝트 생성과 ASan smoke 실행이다.

현재 WSL 사용자가 Docker 소켓을 사용할 수 없으면 한 번만 다음을 실행하고 Windows
터미널에서 WSL을 재시작한다.

```bash
sudo usermod -aG docker "$USER"
```

```powershell
wsl --shutdown
```

다시 WSL을 연 뒤 `docker info`와 `fuzz-pipeline doctor`가 성공해야 한다. Docker
소켓 권한을 모든 사용자에게 여는 방식은 사용하지 않는다.
