# sbom-triage-agent

SW 공급망 취약점을 **"실제로 실행되는가"** 기준으로 분류하고, 무엇부터 어떻게 고칠지 계산하는 에이전트입니다.
롯데 AX 챌린지 2026 · 롯데이노베이트 과제("SW 공급망 스캐닝 AI 에이전트") 예선용 프로토타입입니다.

스캐너는 CVE를 수백 건씩 쏟아내지만, 그 숫자는 실제 해야 할 일을 크게 부풀립니다.

- **CVE 개수 ≠ 조치 개수** — 대부분 프레임워크가 버전을 관리하는 전이 의존성이라, Spring Boot 패치 한 줄로 함께 해결됩니다.
- **심각도 ≠ 실제 위험** — CRITICAL이어도 EPSS(악용 확률)가 1%대인 반면, 실제 악용이 확인된(KEV) 취약점은 수백 건 속에 묻힙니다.
- **들어 있음 ≠ 실행됨** — Kafka 압축 코덱은 압축 설정이 없으면 돌지 않고, Swagger가 꺼진 서비스의 문서화 라이브러리도 실행되지 않습니다. 반대로 Tomcat은 import하지 않아도 매 요청 실행됩니다.

## 동작 방식 — 사실은 도구가, 판단은 에이전트가, 검증은 규칙이

```
 빌드 산출물(jar/war) ─┐
                     ├─ ① 수집   Syft(SBOM, CycloneDX) → Trivy(CVE) → EPSS·KEV 결합
 의존성 트리 ─────────┤
 (Gradle / Maven)    ├─ ② 맥락   도입 경로 · 직접 선언 여부 · 소스 import · 다른 jar 안에 포함(shaded) 여부
 소스 · 설정 ─────────┘
                        ③ 판단   규칙 지식베이스 먼저 → 남은 것만 LLM 에이전트(도구 4개를 스스로 호출)
                                 A 코드가 직접 사용 · B 프레임워크가 실행 · C 설정상 실행 안 됨
                        ④ 조치   Spring Boot BOM 대조 → Boot 패치로 해결 / 버전 오버라이드 /
                                 직접 고정 의존성 업그레이드 / 버전 라인 전환 필요
                        ⑤ 검증   근거 ID 인용 검사 → 실패하면 "실행됨"으로 되돌리고 사람 검토
                                 ↓
                        HTML 리포트 · 여러 서비스 역조회(새 CVE → 어디서 실제 실행 중인가)
```

- **규칙 지식베이스** (`kb.py`): 프레임워크 핵심 라이브러리(B), Swagger 설정(C/B), Kafka 압축 미사용(C), AWS 동기 클라이언트의 Netty 미사용(C). "실행 안 됨" 규칙은 조건이 하나라도 애매하면 에이전트에게 넘깁니다.
- **에이전트** (`judge.py`): gpt-5.5, Tool Calling — 설정 검색 · 소스 검색 · 의존성 경로 · 빌드 파일 검색. 같은 경로로 들어온 패키지는 묶어서 1회 판단하고, 묶음끼리는 병렬로 처리합니다.
- **검증**: 존재하지 않는 근거 ID, 입력에 없는 CVE ID, 검색 근거 없는 C 판정, 직접 선언 의존성의 C 판정을 차단합니다.

## 실측 결과

본인이 개발에 참여한 Spring Boot 서비스 4개 기준 (자세한 과정: [`docs/experiment-log.md`](docs/experiment-log.md))

| | 스캔 | Boot 패치 후 | 실제 실행됨 | 지금 조치(실행되며 CRITICAL/HIGH·KEV) |
|---|---|---|---|---|
| 4개 서비스 합계 | 363건 | 107건 | 72건 | **42건** |

- **조치 계산 검증**: 한 레포에서 실제로 Boot 버전을 올려 재스캔 → 남은 취약점 45건 = 예측 45건 (패키지 15개 중 12개 정확, 차이는 업그레이드 중 바뀌는 의존성)
- **분류 정확도** (정답 라벨을 LLM 실행 전에 고정, 튜닝용/검증용 분리)
  - 규칙 없이 에이전트만: 검증 레포 87~90% (3~4회 반복)
  - 규칙 + 에이전트: 규칙을 만들기 전에 정답을 고정한 Kotlin 레포 21/21 × 3회
  - gpt-5.5 기준 위험한 오판(실행되는 것을 "실행 안 됨"으로 낮춤) 0건
- **비용·시간**: 레포 1개 28~90초, LLM $0.08~0.68. 규칙·병렬화로 4개 합계 873초 → 187초(−79%), $3.01 → $1.19(−60%)
- **대응 범위**: Gradle·Maven, Java·Kotlin, Boot jar·WAR, Spring Boot가 아닌 프로젝트(전자정부 프레임워크 공식 샘플), 지원이 끝난 버전 라인, shaded 라이브러리

예시 리포트: [`examples/world-engine-report.html`](examples/world-engine-report.html), [`examples/egov-sample-report.html`](examples/egov-sample-report.html) (다운로드 후 브라우저로 열기)

## 실행

필요한 것: Python 3.11+(표준 라이브러리만 사용), [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy), 대상 프로젝트의 Gradle 또는 Maven

```bash
export OPENAI_API_KEY=...            # 규칙만 쓸 때는 --no-llm으로 생략 가능

# 레포 하나: 빌드 → SBOM → 스캔 → 판정 → 조치 → runs/<name>/report.html
python3 prototype/run.py <gradle 또는 maven 모듈 경로> --name my-service
python3 prototype/run.py <경로> --name my-service --skip-build --no-llm      # 빠르게, 비용 0

# 외부 레포처럼 이 도구가 빌드 도구를 실행하면 안 될 때: 직접 만든 의존성 트리를 넘김
python3 prototype/run.py <경로> --build-tool maven --skip-build --deptree-file tree.txt

# 역조회: 새 취약점 가정 → 수정 버전 미만을 쓰는 서비스와 실행 여부
python3 prototype/inventory.py --package io.netty:netty-codec-http --fixed 4.1.137.Final --judge --html lookup.html

# 테스트 (네트워크·LLM 없음)
python3 -m pytest tests
```

## 파일

| 파일 | 역할 |
|---|---|
| `prototype/run.py` | 한 줄 실행 파이프라인 |
| `prototype/buildtool.py` | Gradle·Maven 차이 흡수 (Maven 트리 → Gradle 형식 변환, Boot 버전·직접 버전 감지) |
| `prototype/enrich.py` | EPSS·KEV 결합 |
| `prototype/reach.py` | 도입 경로·직접 선언·소스 import·shaded 분석 |
| `prototype/kb.py` | 규칙 지식베이스 |
| `prototype/judge.py` | LLM 에이전트(도구 호출) + 근거 인용 검증 |
| `prototype/actions.py` | Spring Boot BOM 대조로 조치 계산 |
| `prototype/report.py` | HTML 리포트 |
| `prototype/inventory.py` | 여러 서비스 역조회 |
| `prototype/evaluate.py`, `variance.py`, `compare.py` | 정답 라벨 대비 평가, 반복 편차, 개선 전후 비교 |
| `prototype/labels_*.json` | 정답 라벨 (LLM 실행 전 고정) |
| `docs/00_개념정리.md` | SBOM·CVE·CVSS·EPSS·KEV·전이 의존성·reachability 정리 |
| `docs/experiment-log.md` | 실측 기록 (확인한 것과 가설을 나눠 기록) |

## 한계

- 실행 여부는 **패키지 단위**로 판단합니다. 특정 설정에서만 공격 가능한 CVE의 조건까지는 아직 보지 않아, KEV 취약점은 보수적으로 "지금 조치"에 둡니다.
- 버전업 조치안의 호환성(테스트 통과)은 아직 자동 확인하지 않습니다.
- 규칙 2개(프레임워크 핵심, Swagger)는 평가 레포를 모두 본 뒤 만들어 별도 검증 레포가 없습니다.

## License

MIT
