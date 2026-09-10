# 설계 준수 기준선

이 문서는 대상 탐색부터 사람 검토용 보고서까지 자동 파이프라인이 지켜야 할 기준선이다.
기능을 바꿀 때는 아래 계약과 대응 테스트를 함께 수정한다. 구현이 문서보다 우선하는 것이
아니라, 서로 불일치하면 배포를 중단한다.

| 설계 계약 | 강제 지점 | 회귀 근거 |
|---|---|---|
| 현재 금전 보상 범위가 명시된 후보만 실행 | 탐색 export, 작업 계획, 준비와 장기 실행 직전 정책 재검사 | `test_policy`, `test_pipeline`, 장기 실행 정책 재검사 테스트 |
| 호스트 아키텍처와 명시적 지원 근거가 일치해야 실행 | 탐색 architecture evidence, `native_only` 작업 게이트 | `test_architecture`, ARM64 계획 테스트 |
| x86_64의 일치 프로젝트는 OSS-Fuzz, ARM64는 네이티브 Clang/libFuzzer | 작업 route와 build manifest의 이미지·`uname -m` 확인 | pipeline 및 generic integration 테스트 |
| 하네스는 probe, Quartet P1-P4, coverage 분석을 모두 통과 | worker 상태 전이와 각 산출물 게이트 | runner와 Quartet 관련 테스트 |
| AI는 제한된 소스 문맥으로 하네스·coverage·검증을 보조 | Codex 어댑터, 입력 크기 제한, 캐시와 호출 횟수 제한 | AI, harness generation, validation 테스트 |
| 실행 자원은 CPU·메모리·cgroup·Docker 한도에서 동적 계산 | resource planner와 중앙 에이전트의 선택지 clamp | `test_resources`, capacity 테스트 |
| 정체는 coverage edge/feature 증가로 판정 | `fuzz-progress.json`의 coverage 기준선과 `stalled_seconds` | coverage 정체 테스트 |
| dictionary를 생성했으면 다음 libFuzzer 실행에 실제 전달 | runtime output의 `.dict` 확인과 `-dict=/out/...` | fuzz session command 테스트 |
| x86 OSS-Fuzz만 AFL++ CmpLog, 네이티브는 dictionary와 후속 하네스 | route별 정체 대응 분기 | stall/AFL 및 ARM 계획 테스트 |
| 크래시는 최소화, 깨끗한 환경 3/3 재현, 스택 중복 제거, UBSan 확인 | triage runner | `test_triage` |
| 재현된 결과만 비무기화 PoC와 보고서 초안으로 전달 | validation handoff와 별도 Codex 검증 agent | `test_validation_agent` |
| 정상 서비스 중지는 재개 가능하며 실패 예산을 소모하지 않음 | cancel event, `PipelineInterrupted`, worker 분기 | operator interruption 테스트 |
| 실행 로그와 sanitizer 판정은 세션별로 분리 | 세션 ID가 포함된 fuzz log | runner 세션 테스트 |
| 외부 자동 제출은 없음 | 로컬 산출물만 생성하는 validation 단계 | validation 테스트와 코드 검토 |

배포 전에는 전체 단위 테스트, Ubuntu 24.04 컨테이너 테스트, wheel 설치 검사를 통과해야
한다. 실제 캠페인을 새로 시작할 때 이전 `runs`와 중앙 상태는 삭제하지 않고 시각이 표시된
history 폴더로 이동한다. 새 실행은 빈 상태에서 후보 탐색과 정책 검증부터 시작한다.
