> 공개용 사본: 개발 중 기록(`02_실측기록.md`)에서 개인 서비스 이름과 운영 관련 세부 정보를 지운 버전입니다. 나머지는 원본과 같습니다.

# 실측 기록

> Evidence(실제로 확인한 것)와 Hypothesis(아직 검증 안 한 추정)를 분리해서 적는다.

## 2026-10-29 1차 스캔

### 환경
- syft 1.55.0 (SBOM, CycloneDX JSON) / trivy 0.76.1 (`trivy sbom`)
- 대상: 각 레포 현재 브랜치에서 `./gradlew bootJar -x test`로 **새로 빌드한 jar** (기존 jar는 마지막 커밋보다 오래돼서 재빌드)
  - World Engine server — `develop`, Spring Boot 4.1.0
  - BuzzerBidder server (`WEB7_9_DEVut_BE`) — `fix/load-testing`, Spring Boot 3.5.8
    - 마지막 머지는 main PR #250(2026-01-18). fix/load-testing은 그 위에 미push 커밋 2개(JMeter·부하테스트 데이터·dev yml)뿐이고 `build.gradle` 차이 없음 → **의존성은 main과 동일**
  - World Engine client — 디렉토리 스캔 (package-lock.json)
- 결과 파일: `scans/*.cdx.json`, `scans/*.trivy.json`, `scans/*.enriched.json`
- EPSS: api.first.org (2026-10-28 기준값) / KEV: CISA 피드 (2026-10-29 다운로드)

### Evidence

| 대상 | SBOM 구성요소 | 취약점 | 취약 패키지 | CRITICAL+HIGH | 수정버전 있음 | KEV | EPSS ≥ 0.01 |
|---|---|---|---|---|---|---|---|
| WE server | 93 | 19 | 7 | 13 | 19 | 0 | 0 |
| WE client | 11 | 0 | 0 | 0 | 0 | - | - |
| BB server | 201 | 141 | 34 | 61 | 134 | 0 | 9 |

- WE client: package-lock.json에는 83개인데 SBOM엔 10개(+lock 파일 1) — syft가 기본값으로 **devDependencies 제외**
- KEV(실제 악용 확인) 해당: 두 서버 모두 **0건**
- EPSS 최고값: BB 0.026 (commons-lang3, MEDIUM), WE 0.007 — CRITICAL 등급도 EPSS는 0.006~0.017 수준
- BB 취약점 141건의 패키지 그룹: netty 38, spring 33(+security 6, data 5, kafka 3 등), jackson 16, tomcat 16, lz4 8, snappy 3, …

### Hypothesis (검증 필요)
1. **"CVE 개수"가 아니라 "조치 단위"로 세면 훨씬 줄어든다.** BB 141건 중 대부분(대략 129건 추정 — lz4·snappy·redisson 제외)이 Spring Boot가 버전을 관리하는 패키지 → Spring Boot 패치 버전 하나 올리면 대부분 해결될 수 있음. → 실제로 Boot 버전 올려서 재스캔해 확인할 것
2. **EPSS/KEV만으로는 변별력이 약하다.** 이번 표본에선 거의 모두 "낮음"으로 뭉쳐서, CRITICAL 61건 사이 순서를 정해주지 못함 → 실제 사용 여부(reachability)·외부 노출 여부가 주 변별 요소가 돼야 할 가능성. 단, 표본 2개 레포라 일반화 금지
3. devDependencies 제외가 맞는 기본값인지는 관점에 따라 다름 (런타임 노출 ↔ 빌드 체인 공격)

## 2026-10-29 Hypothesis 1 검증 — Spring Boot 패치 버전업

### 방법
- `git archive main`으로 BB를 `work/bb-upgrade/`에 복사 (원본 레포 무변경)
- `build.gradle` 한 줄: Spring Boot `3.5.8` → `3.5.16` (Maven Central 기준 3.5.x 최신)
- `bootJar -x test` 빌드 → syft → trivy 재스캔 (`scans/bb-boot3516.*`)

### Evidence
| | 취약점 | CRITICAL+HIGH | EPSS ≥ 0.01 |
|---|---|---|---|
| Boot 3.5.8 (현재) | 141 | 61 | 9 |
| Boot 3.5.16 | **45** | 23 | 2 |

- **build.gradle 한 줄로 141 → 45 (96건, 68% 해소)**
- 남은 45건 구성
  - Boot가 관리하는 라이브러리지만 **Boot 3.5.16이 싣고 있는 버전보다 더 새 패치에서 수정된 것**: jackson-databind 2.21.4(수정 2.21.5~2.21.7), tomcat 10.1.55(수정 10.1.58~59), netty 4.1.135 등 → Boot 다음 패치를 기다리거나 버전 속성 오버라이드로 해결
  - **내가 버전을 직접 고정한 것**: `redisson-spring-boot-starter:3.17.0` (build.gradle 62행) → Boot 버전업과 무관, 따로 올려야 함
  - 그 밖에 kafka 쪽에서 딸려오는 lz4/snappy 등 전이 의존성
- 변경 없음: commons-lang3 3.17.0, log4j-api 2.24.3 (원인 미확인)

### Hypothesis 1 판정
- "조치 단위로 세면 크게 줄어든다" → **지지됨**. 단 사전 추정(~129건 해소)보다 적은 96건 — 최신 Boot도 라이브러리 최신 패치를 바로 따라가진 못함
- 조치 단위 구조(잠정): ① Boot 패치 버전업 ② Boot 관리 버전 오버라이드 ③ 직접 고정한 의존성 개별 업그레이드 ④ 전이 의존성 개별 대응

### 주의 (아직 확인 안 한 것)
- **테스트는 안 돌림**(`-x test`). 컴파일·패키징만 성공 → "버전업해도 안 깨진다"는 아직 주장 불가. 기획서의 "breaking change 검토" 단계가 바로 이 빈칸

## 2026-10-29 Reachability 레벨 1 + 직접/전이 (BB, Boot 3.5.16 기준 45건)

### 방법 (`prototype/reach.py`)
- 직접/전이: `./gradlew dependencies --configuration runtimeClasspath` 트리 → 각 취약 패키지가 어느 직접 의존성 밑으로 들어왔는지
- 사용 여부: boot jar 안의 해당 라이브러리 jar에서 **정확한 Java 패키지 집합**을 뽑아, `src/main/java`의 import 패키지와 정확히 일치하는지
- 1차 구현 버그(자체 발견·수정): 패키지 접두어를 3단계로 잘라서 `org.springframework.web.bind.annotation`(spring-web의 @RestController 등) import 82건이 webmvc/webflux 사용으로 잘못 잡힘 → 정확한 패키지 일치로 수정 (webflux 32→4파일, webmvc 32→2파일)

### Evidence
- 직접 의존성 28개. **취약 패키지 15개 전부 전이 의존성** (직접 선언한 건 하나도 없음; redisson도 직접 선언한 건 starter)
- 소스 import 있음: 6개 패키지 / 20건 — jackson-databind, tomcat-embed-core, spring-webflux, jackson-core, spring-webmvc, redisson
- import 없음: 9개 패키지 / 25건 — netty 5종, lz4-java, snappy-java, commons-lang3, log4j-api
- tomcat-embed-core의 "사용"은 `jakarta.servlet(.http)` — 서블릿 API 인터페이스(Filter 등)이지 CVE가 있는 Tomcat 내부 구현이 아님
- lz4/snappy는 spring-kafka 밑. `src/main` 설정·코드 어디에도 `compression`/`lz4`/`snappy` 없음 → Kafka 기본값(compression.type=none)
- netty는 import 0이지만 webflux·AWS S3 SDK 밑으로 들어옴. 소스에서 `WebClient`·`software.amazon.awssdk` 사용 파일 7개 존재

### 해석 — import 여부는 "사용/미사용" 이분법으로 쓰면 틀린다
| 분류 | 예 | import 신호의 의미 |
|---|---|---|
| A. 직접 사용 | jackson-databind, redisson, webflux 클라이언트 | 신호 유효 |
| B. 프레임워크가 대신 실행 | tomcat, netty(WebClient·S3 경유) | **import 없어도/엉뚱한 import여도 매 요청 실행됨** → 신호 무의미, 우선순위 낮추면 안 됨 |
| C. 설정에 따라 꺼져 있음 | lz4/snappy (Kafka 압축 미설정) | import가 아니라 **설정**이 근거 → 우선순위 낮출 근거 있음 |

- → 에이전트 설계에 반영할 점: import만 보지 말고 "그 패키지를 끌고 온 직접 의존성이 실제로 쓰이는가" + "관련 설정이 켜져 있는가"까지 봐야 함. 이 판단(어느 분류인지)이 LLM이 근거를 인용하며 할 일의 실제 예시
- 표본: 레포 1개. B/C 분류 기준은 아직 손으로 판단한 것

## 2026-10-29 LLM 판단 에이전트 1차 (`prototype/judge.py`, `evaluate.py`)

### 구조
- 패키지별 초기 근거(E*: CVE·CVSS·EPSS·KEV·fixed 버전 / 의존성 경로 / import 결과) + **에이전트가 직접 호출하는 도구 4개**(설정 검색, 소스 검색, 의존성 경로, build 파일 검색 → 결과마다 T* ID)
- 출력: 분류 A/B/C, 우선순위 P1~3, 조치유형 1~4, 근거 인용 달린 주장 목록
- 검증기(결정론): 존재하지 않는 근거 ID 인용 / 인용 없는 주장 / 근거에 없는 CVE ID / C인데 검색 근거 없음 / 직접 선언 의존성을 C로 → **하나라도 걸리면 B로 되돌리고 needs_review**
- 정답 라벨은 **LLM 실행 전에 고정**: `labels_bb.json`(15, 튜닝용), `labels_we.json`(7, 검증용)

### Evidence — 분류 일치
| 모델·프롬프트 | BB (15) | WE (7) | 위험한 오판(실제 실행 → C) |
|---|---|---|---|
| gpt-5.4-mini v1 | 12 | 6 | **1** (WE postgresql → C, P3) |
| gpt-5.4-mini v2 | 11 | 5 | 0 |
| gpt-5.5 v2 | **14** | **7** | 0 |

- v1 postgresql 오판 원인 3개: ① **내 도구 버그** — build_file이 `build.gradle`만 보고 `.kts`를 못 봄 ② WE는 datasource를 설정 파일이 아니라 spring-boot-docker-compose가 자동 연결 → "설정 없음"을 "안 씀"으로 오해 ③ 초기 근거 E2(직접 선언=true)를 인용하면서 "직접 선언 흔적 없음"이라고 씀 → 인용 ID 존재 여부만 보는 검증기가 못 잡음
- v2 추가 규칙(기본값 꺼짐도 C, 끌고 온 의존성 설정도 검색, prod 기준, "흔적 없음"만으론 C 아님): **mini는 규칙을 거의 안 따름**(여전히 패키지명으로만 검색). gpt-5.5는 따름 — commons-lang3에서 springdoc prod `enabled: false`까지 찾아 C 판정
- gpt-5.5 남은 오답: lz4-java (C → B, 안전한 방향). snappy는 C로 맞춤 — 같은 종류인데 결과가 갈림 → 1회 실행이라 편차 미측정
- 모델 간 A/B 경계는 흔들림(jackson-core, spring-webmvc가 실행마다 A↔B). 우선순위엔 영향 적음(둘 다 "실행됨")

### 라벨 수정 1건 (투명성)
- gpt-5.5가 netty-codec을 C로 판정 → 처음엔 오답 처리했으나 재검토: 해당 CVE-2026-59901은 bzip2 디코더 한정. BOOT-INF/lib 전체 jar 바이트코드에서 `Bzip2Decoder` 참조는 netty-codec 자신뿐, 소스도 미사용 → **결론은 타당**. 라벨을 B/C 둘 다 인정으로 수정 (위 표는 수정 후 점수)
- 단, **에이전트가 댄 근거는 틀림**: "netty-codec-compression이 클래스패스에 없다" — Netty 4.1에선 Bzip2 클래스가 netty-codec jar 안에 있음(23개 확인). 결론 맞음·근거 틀림 → 현 검증기로는 못 잡는 유형

### 해석 (Hypothesis)
1. 패키지 단위 분류보다 **CVE(취약 함수) 단위 판단**이 더 정확할 수 있다 — netty-codec 사례. 그리고 "취약 클래스를 누가 참조하는가"는 **바이트코드 검색으로 결정론적으로 확인 가능** → LLM 추측이 아닌 도구로 넣을 후보 (레벨 1.5 reachability)
2. 조치유형(1~4)은 LLM마다 들쭉날쭉 → 의존성 트리·BOM·build 파일로 **규칙 계산**하는 게 맞아 보임. LLM이 할 일 아님
3. "기본값이 꺼짐" 같은 지식은 LLM 기억에 맡기면 불안정(lz4/snappy 갈림) → 자주 나오는 기본값은 규칙/지식베이스로
4. 이번 라운드에서 WE 오답을 보고 규칙을 추가했으므로 WE도 더 이상 순수 검증용 아님 → 진짜 held-out은 세 번째 레포 필요(데브코스 팀 프로젝트 BE)

## 2026-10-29 반복 실행 편차 + 세 번째 레포 held-out (gpt-5.5, v2 고정)

### 반복 실행 (BB·WE, 같은 설정 4회)
| | 실행별 일치 | 위험한 오판 |
|---|---|---|
| BB (15) | 14, 13, 13, 13 | 0 |
| WE (7) | 7, 7, 7, 7 | 0 |
- lz4-java: 4회 모두 B (오답) — "Kafka 압축 기본값 none" 추론을 **일관되게** 못 함
- snappy-java: C, B, B, B — 1회차 정답은 운이었음
- log4j-api: B/C 오감(둘 다 정답 처리된 애매 건)
- 조치유형(action)은 gpt-5.5에선 같은 패키지에 대해 4회 동일 → mini 때의 들쭉날쭉은 모델 문제였을 가능성

### 세 번째 레포 held-out — NBE7-9-2-Team3 backend (main, Boot 3.5.6)
- `git archive main`으로 복사 (원본에 미커밋 변경 있어서 건드리지 않음). 취약점 101건 / 패키지 20개 / CRITICAL+HIGH 45 / KEV 0 / EPSS≥0.01 7건
- 라벨 20건을 **v2 프롬프트 확정 후, LLM 실행 전에** 고정 (`labels_t3.json`). 어려운 케이스 2개 포함
  - netty 4종(31건): AWS SDK s3 경유인데 소스는 동기 `S3Client`·`S3Presigner`만 사용 → 동기는 apache-client, netty-nio-client는 비동기 전용 → **C**
  - commons-lang3: springdoc 경유인데 이 레포엔 끄는 설정 없음 → Swagger 활성 → **B** (BB와 반대)

| | 실행별 일치 | 위험한 오판 | 검증 실패 폴백 |
|---|---|---|---|
| T3 (20) | **17, 19, 17** | **0** | 0 |

- commons-lang3: 3회 모두 B — BB(C)와 반대 상황을 설정 근거로 정확히 구분
- 오답은 전부 netty C → B (안전한 방향). netty-handler CCC, netty-codec BBB, codec-http/http2 BCB — **같은 근거를 공유하는 형제 패키지끼리 판정이 갈림**
- run1 vs run2 (codec-http): 둘 다 "S3AsyncClient 사용 없음, apache-client 존재"까지 **같은 근거를 다 찾음**. run1은 "보수적으로 B", run2는 C → 근거 수집이 아니라 **최종 판단 단계의 편차**. run1은 도구 18회 호출

### 누적 (gpt-5.5 v2)
- 판정 148건(BB 60, WE 28, T3 60) 중 **위험한 오판 0건**
- 순수 held-out(T3) 일치율 53/60 = 88%. 오답 7건 전부 "실행 안 되는 걸 실행된다고 봄" → 위험이 아니라 **조치 대상 축소를 덜 한 것**(효율 손실)

### 해석 (Hypothesis)
1. 형제 패키지 판정 불일치 → 패키지마다 따로 판단하지 말고 **같은 도입 경로(예: s3 → netty-nio-client → netty-*) 단위로 한 번 판단해 전파**하면 일관성↑, 호출 수↓
2. 남은 오답은 "증거는 다 모았는데 C라고 말 못 함" — "확신 없으면 B" 규칙의 대가. 의도된 보수성으로 설명 가능하되, 자주 나오는 패턴(동기/비동기 HTTP 클라이언트, Kafka 압축 기본값)은 규칙·지식베이스로 빼는 게 맞아 보임

## 2026-10-29 비용 — 실측과 절감 파이프라인(v3) 비교

### 오늘 실험 총비용 (OpenAI 대시보드)
- gpt-5.5: input $11.397 / output $4.369 / cached $0.34 · gpt-5.4-mini: input $0.718 / output $0.082 / cached $0.007 → 합계 약 $16.9, 약 400만 토큰
- 가격(USD/1M, input·cached·output): gpt-5.5 5.00·0.50·30.00, gpt-5.4-mini 0.75·0.075·4.50 — 대시보드 청구액 역산과 일치
- 판정당 평균: gpt-5.5 약 $0.11, mini 약 $0.018. **비용의 2/3가 gpt-5.5 입력 토큰** — 도구 호출마다 대화 전체를 재전송하는 구조

### v3 파이프라인 (`PIPELINE=v3`)
1. 규칙 A: 소스가 직접 import → LLM 생략
2. 규칙 B: 직접 선언 + import 없음 → LLM 생략 (C 불가)
3. 나머지는 (groupId, 도입 경로) 단위로 묶어 1회 판단 → 묶음 전체에 전파
4. 도구 호출 예산 8회, 도구 결과 12줄 제한
- T3 20건 → 규칙 11건 + LLM 묶음 6개 (netty 4종이 한 묶음)

### Evidence — T3, gpt-5.5, 토큰 실측 (각 1회)
| | API 호출 | 입력 토큰(캐시) | 출력 토큰 | 비용 | 분류 일치 | 위험한 오판 |
|---|---|---|---|---|---|---|
| v2 (패키지별 판단) | 52 | 136,797 (52,992) | 44,216 | **$1.77** | 19/20 | 0 |
| v3 (규칙+묶음) | 15 | 39,546 (11,136) | 9,594 | **$0.44 (−75%)** | 15/20 | 0 |

- v2의 이번 회차 19/20은 기존 3회(17·19·17)와 합쳐 범위 17~19
- v3 오답 5건
  - tomcat-embed-core: 규칙 A가 오판 — import한 건 `jakarta.servlet` 인터페이스(tomcat jar 안에 들어 있는 서블릿 API). 앞서 확인한 함정을 규칙에 반영 안 함. A/B 둘 다 "실행됨"이라 우선순위 영향은 없음
  - netty 4종: 묶음 1회 판단이 B → **4건이 한꺼번에 틀림**. 묶음은 오류도 묶어서 냄(상관된 오류). 도구 예산 8회에 걸림(v2에서 C를 맞힌 회차는 11회, 못 맞힌 회차는 18회 사용)

### 해석 (Hypothesis)
- 비용 절감은 구조로 확실히 됨(−75%). 정확도 하락은 netty 묶음 1건에서 대부분 발생 → 1회 실행이라 v2 편차 범위와 비교 불가, 반복 측정 필요
- tomcat 오판은 결정론적으로 고칠 수 있음: 스펙 인터페이스 네임스페이스(`jakarta.*`, `javax.*`) import는 규칙 A 근거에서 제외

### 다음
- [x] Hypothesis 1 검증
- [x] reachability 1차 / 직접·전이 구분
- [x] LLM 판단 1차
- [x] 같은 설정 반복 실행으로 편차 측정
- [x] 세 번째 레포로 held-out 평가
- [x] 비용 실측 + v3 1회 비교
- [x] v3 개선(jakarta 제외, 묶음 도구 예산) 후 반복 측정

## 2026-10-29 v3 개선판(v3b) 반복 측정 — T3, gpt-5.5, 3회

### 변경
- 규칙 A 근거에서 `jakarta.*`/`javax.*` import 제외 → tomcat은 LLM 판단으로 넘어감 (규칙 결정 11 → 10건)
- 묶음(2개 이상) 판단의 도구 예산 8 → 12회

### Evidence
| | 회차별 일치 (20) | 평균 | 위험한 오판 | 1회 비용 (평균) | API 호출 |
|---|---|---|---|---|---|
| v2 (패키지별) | 17, 19, 17, 19 | 18.0 (90%) | 0 | $1.77 (토큰 기록한 1회) | 52 |
| v3b (규칙+묶음) | 16, 20, 16 | 17.3 (87%) | 0 | **$0.55 (−69%)** | 18~19 |

- tomcat: 3회 모두 B로 정답 (규칙 수정 효과)
- v3b 오답은 전부 netty 묶음(B, C, B) — 맞으면 20/20, 틀리면 16/20. **묶음이라 결과가 양극단**
- netty 정답률(패키지 단위): v2 8/16 = 50% (4회), v3b 4/12 = 33% (3회). 표본이 작아 차이를 단정할 수 없음
- spring-expression 우선순위 P1/P2 흔들림 (분류는 3회 모두 정답)
- v3 관련 실험 추가 비용: 약 $3.9 (v2 기준 1회 $1.77 + v3 1회 $0.44 + v3b 3회 $1.65)

### 결론 (현 시점)
- **비용 −69%, 평균 정확도 −3%p, 위험한 오판 0 유지.** 남은 오답은 모두 "netty가 실행 안 되는데 실행된다고 봄" 1종 = 효율 손실만
- 남은 개선 후보(본선): 동기/비동기 HTTP 클라이언트처럼 반복되는 패턴을 규칙(지식베이스)으로 → netty 묶음은 LLM 없이 C 판정 가능
- [ ] (본선 확장) 바이트코드 참조 검색 도구 / 조치유형 규칙 계산 / 도입 경로 단위 판단 / 기본값 지식베이스
- [ ] reachability 1차: 취약 패키지를 소스에서 실제 import하는지
- [ ] 직접/전이 의존성 구분 (`./gradlew dependencies`)

## 2026-10-30 개선 1·4 — 한 줄 실행 + HTML 리포트 + 조치 규칙 계산

### 한 줄 실행 (`prototype/run.py`)
- `run.py <gradle 모듈> [--name] [--skip-build] [--no-llm]` → 빌드 → 의존성 트리 → SBOM(syft) → trivy → EPSS·KEV → 도입 경로·import → 규칙+에이전트 판정(v3) → 조치 계산 → `runs/<name>/report.html`
- Spring Boot 현재 버전·같은 라인 최신 패치는 build 파일과 Maven Central 메타데이터에서 자동 계산 (프롬프트의 Boot 버전도 자동 주입)
- BuzzerBidder 원본(Boot 3.5.8, 141건, 34패키지): LLM 호출 42회, **$1.25**, 394초. 원본 레포 git 변경 없음
- 규칙만(`--no-llm`) 실행: Team3 37초, 비용 0

### 조치 규칙 계산 (`prototype/actions.py`) — LLM에서 제외
- Spring Boot 최신 패치의 BOM(`spring-boot-dependencies`, import된 하위 BOM까지 재귀)을 받아 패키지별로: 1 Boot 패치로 해결 / 2 관리 버전 오버라이드 / 3 직접 고정 의존성 업그레이드 / 4 개별 대응
- 수정 버전이 같은 major.minor 라인에 없으면 "라인이 바뀌는 업그레이드 — 프레임워크 전환과 함께 검토"로 별도 표시 (spring-webmvc/webflux 6.2 → 7.0.9)
- 우선순위도 규칙으로: 실행됨(A·B) + Boot 패치 후 남는 취약점에 CRITICAL/HIGH/KEV → P1. (LLM 우선순위는 실행마다 흔들렸음)

### Evidence — BOM 예측 vs 실제 재스캔 (BB, Boot 3.5.8 → 3.5.16)
- 예측 남는 취약점 **45건** = 실제 재스캔 **45건**
- 패키지 단위: 15개 중 **12개 정확**. 불일치 3개가 서로 상쇄돼 합계가 일치한 것
  - lz4-java 예측 8 / 실제 6: kafka-clients가 올라가며 lz4가 **다른 좌표의 포크**(`org.lz4` → `at.yawk.lz4`)로 교체됨 — BOM으로 예측 불가
  - jackson-databind 8/9, tomcat-embed-core 3/4: **새 버전에만 해당하는 취약점**이 업그레이드 후 나타남 — 현재 버전 기준 계산으론 안 보임
- → 리포트에 "BOM 대조 예측이며 패치 후 재스캔으로 확인" 명시

### 리포트 결과 (BB)
- 141 → Boot 패치 후 45 → 지금 조치(실행되며 CRITICAL/HIGH·KEV) **24건** → 실행 안 됨 1패키지
- 사람 라벨 기준 계산(20건)과 차이 4건 = 에이전트가 lz4·snappy·netty-codec을 C 대신 B로 본 것 (기존에 알려진 보수적 오답)
- 맨 위 P1 카드: Redisson — "직접 고정한 redisson-spring-boot-starter:3.17.0을 redisson 3.22.0 이상을 쓰는 버전으로 업그레이드"

## 2026-10-30 개선 2 — 역조회 (`prototype/inventory.py`)

### 구조
- `run.py`가 취약 패키지뿐 아니라 **SBOM 전체 구성요소**의 사용 인덱스(직접 선언·도입 경로·소스 import)를 `summary.json`에 저장 (BB 124개 구성요소)
- `inventory.py --cve <ID>`: 이미 스캔된 취약점이 어느 서비스에 있고 실행되는지
- `inventory.py --package <g:a|a> --fixed <ver> [--judge] [--title] [--html]`: **새 취약점 가정** — 수정 버전 미만을 쓰는 서비스와 실행 여부. 실행 여부 판단 순서: 기존 판정 → 사용 인덱스(import=A, 직접 선언=B) → 둘 다 아니면 "판정 필요", `--judge`면 그 서비스만 에이전트가 즉석 판단

### Evidence
- `--cve CVE-2023-42809` → BuzzerBidder 1곳, redisson 3.17.0, 실행됨(코드 직접 사용)
- `--package jackson-databind --fixed 2.21.7` → BB(2.19.4, A), Team3(2.19.2, B 직접 선언). WE는 `tools.jackson.core`(Jackson 3, 다른 좌표)가 **이름만 같아 걸림** → 서로 다른 group이 일치하면 경고하도록 수정
- `--package io.netty:netty-codec-http --fixed 4.1.137.Final --judge` → BB(B, 기존 판정), Team3("판정 필요" → 에이전트 3회 호출 **$0.079**로 즉석 판정 B), WE 미포함
  - Team3 판정 B는 라벨상 오답(동기 S3Client라 netty 미사용 = C) — 개선 3(규칙 지식베이스) 대상. 규칙 추가 후 같은 조회 재실행해 비교할 것

## 2026-10-31 개선 3·5 — 규칙 지식베이스 + Kotlin 지원 + 네 번째 레포 held-out

### Kotlin 지원
- import 정규식이 세미콜론 없는 Kotlin(`import a.b.C`, `import a.b.C as D`)도 처리, 소스 탐색을 `src/main` 아래 `.java`·`.kt`로 확장 (NBE7-9-3은 `.kt` 158개가 `src/main/java`에 있음). Java 레포 결과 회귀 없음 확인 (Team3 10개/45건 동일)

### 순서 (정직한 측정을 위해)
1. 네 번째 레포 NBE7-9-3-Team3(Kotlin, main aa09cce, Boot 3.5.6, 102건/21패키지)을 규칙만으로 분석
2. **규칙 구현 전·LLM 실행 전에** 라벨 21건 고정 (`labels_t4.json`)
   - 핵심: Team3와 비슷하지만 **Redis(Lettuce) 경로가 추가** — netty-codec-http/http2는 s3 경유만(동기 S3Client → C), netty-handler/codec은 Redis 경로 있음(LettuceConnectionFactory 직접 구성 + RedisTemplate 사용 → B). "S3 경유 netty는 C"를 대충 일반화하면 틀리는 정밀도 시험
3. 규칙 지식베이스 구현 (`prototype/kb.py`) → 측정

### 규칙 (결정론, 보수적 — 조건이 하나라도 애매하면 에이전트로 넘김)
- `kb-aws-sync`: 패키지로 가는 **모든** 의존성 경로가 `software.amazon.awssdk:netty-nio-client`를 거치고, 소스에 비동기 SDK 흔적(AsyncClient·NettyNioAsyncHttpClient·S3TransferManager 등)이 없으면 C
- `kb-kafka-codec`: lz4/snappy/zstd로 가는 모든 경로가 kafka-clients를 거치고, 설정·소스에 compression 설정이 없으면 C. 단 "다른 서비스가 압축해 보낸 토픽을 소비하면 해제 경로 실행 가능 — 토픽 생산자 확인" 단서를 근거에 명시
- 4개 레포 dry-run: 규칙에 걸린 8건(BB lz4·snappy, Team3 netty 4종, Team4 netty-http 2종) **전부 라벨과 일치**. Team4 netty-handler/codec(Redis 경로)과 BB netty(WebClient 경로)는 규칙이 적용되지 않음 = 의도대로

### Evidence — Team4 held-out, gpt-5.5, v3 파이프라인 + 규칙, 3회
| | 회차별 일치 | 위험한 오판 | 비용/회 | 호출 |
|---|---|---|---|---|
| Team4 (21) | **21, 21, 21** | 0 | $0.63~0.70 | 22~25 |
- 3회 모두 동일 판정. netty-http 2종 = 규칙 C, Redis 경로 netty 2종 = 에이전트 B(3/3 정답), commons-lang3 = 에이전트 B(Swagger 켜짐, 정답)
- **해석 주의**: 이 레포에서 정답이 C인 건(netty-http 2종)은 규칙이 해결. 애매 건(log4j-api, spring-data-keyvalue)은 에이전트가 보수적으로 B(라벨상 B/C 모두 허용). 즉 21/21은 "규칙+에이전트 조합"의 성적이고, 에이전트 단독의 C 판정 능력을 보여주는 숫자는 아님
- 규칙 반영 후 Team3 재측정 20/20 — 단 규칙이 Team3 오답을 보고 만든 것이라 held-out 아님

### 최종 실행 (규칙 반영, 각 1회) — 4개 레포 퍼널
| 레포 | 스캔 | Boot 패치 후(예측) | 그중 실행됨 | 지금 조치(P1) | 실행 안 됨(C) | LLM 비용 |
|---|---|---|---|---|---|---|
| BuzzerBidder | 141 | 45 | 32 | 19 | 13 | $1.12 (35회) |
| World Engine | 19 | 2 | 2 | 1 | 0 | $0.80 (8회) |
| Team3 | 101 | 30 | 17 | 10 | 13 | $0.39 (14회) |
| Team4 | 102 | 30 | 20 | 12 | 10 | $0.70 (22회) |
| **합계** | **363** | **107** | **71** | **42** | **36** | **$3.01** |
- "지금 조치" = 실행됨(A·B) 패키지의 Boot 패치 후 남는 취약점 중 CRITICAL/HIGH/KEV 개수 (에이전트+규칙 판정 기준)
- 기존 3개 레포 기준(라벨 기준, 실제 재스캔 사용)은 261→79→56→32였음. 이번 값은 에이전트 판정 + BOM 예측 기준이라 정의가 다름 — 제출 글 갱신 시 하나로 통일할 것

### 역조회 재실행 (netty-codec-http < 4.1.137.Final)
- 규칙 전: Team3 "판정 필요" → 에이전트 즉석 판정 **B(오답)**, $0.079
- 규칙 후: BB 실행됨(B), **Team3·Team4 실행 안 됨(C, kb-aws-sync)**, World Engine 미포함 — LLM 호출 0회

### 이틀간(10/30~31) 추가 LLM 비용: 약 $5.7 (BB 첫 실행 $1.25, 역조회 $0.08, Team4 3회 $2.03, 최종 3레포 $2.31)

## 2026-11-01 성능 개선 — 병렬화 + 규칙 2개 추가 + 대용량 파일 토큰 폭증 수정

### 변경
1. **판단 병렬화**: 묶음 판단끼리 `ThreadPoolExecutor`(기본 4)로 병렬. 한 판단 안의 도구 호출은 순차 유지. usage 갱신은 lock, 429면 `retry-after` 준수 + 재시도 5회
   - 계정 한도 확인(응답 헤더): gpt-5.5 5,000 RPM / 1M TPM, gpt-5.4-mini 5,000 RPM / 2M TPM → 동시 4개(분당 수십 회, ~10만 TPM)는 한도의 ~10%. 이번 실행 429 0회
   - World Engine 때(`PARALLELISM=2`, 3분→83초)와 달리 병목은 한도가 아니라 "가장 긴 판단 1건의 순차 도구 호출"
2. **규칙 `kb-framework-core` (B)**: tomcat(starter-tomcat 경로), jackson(starter-json 경로), logback(starter-logging 경로), spring-expression(spring-context 경로) → 실행됨. B 규칙은 틀려도 안전한 방향. 대신 "Tomcat 특정 기능만 꺼짐" 같은 CVE 단위 C 판단은 포기 (한계)
3. **규칙 `kb-springdoc` (C/B)**: 모든 경로가 springdoc 경유일 때만. 기본/prod 설정에 `springdoc.api-docs.enabled=false`면 C, 아니면 B (간단한 YAML/properties 파서)
4. **토큰 폭증 수정**: World Engine `resources/static/assets/index-*.js`(압축된 프론트 번들, 한 줄이 매우 김)가 설정 검색에 걸려 호출당 ~5만 토큰(8회에 입력 41만 토큰, $1.48). → 설정 검색은 `*.yml/*.yaml/*.properties/*.xml`만, grep 결과는 줄당 300자로 자름

### 규칙 dry-run (LLM 비용 0)
- 4개 레포에서 규칙이 판정한 23건 **전부 라벨과 일치**. springdoc 규칙은 BB(prod에서 꺼짐 → C)와 Team3/4(켜짐 → B)의 반대 상황을 구분
- **주의**: 새 규칙 2개는 4개 레포를 모두 본 뒤 만든 것이라 held-out 검증이 아님

### Evidence — 4개 레포 1회씩, gpt-5.5 (`prototype/compare.py runs/_old/pre-parallel runs`)
| 레포 | 시간 | LLM 호출 | 비용 | 라벨 일치 | 판정 주체(규칙·에이전트) |
|---|---|---|---|---|---|
| BuzzerBidder | 362s → 90s | 35 → 23 | $1.12 → $0.68 | (라벨 없음) | 18·16 → 22·12 |
| World Engine | 77s → 28s | 8 → 7 | $0.80 → $0.18 | 7/7 → 7/7 | 3·4 → 4·3 |
| Team3 | 120s → 29s | 14 → 3 | $0.39 → $0.08 | 20/20 → 20/20 | 14·6 → 19·1 |
| Team4 | 314s → 40s | 22 → 8 | $0.70 → $0.24 | 21/21 → 21/21 | 12·9 → 17·4 |
| **합계** | **873s → 187s (−79%)** | **79 → 41** | **$3.01 → $1.19 (−60%)** | 위험한 오판 0 유지 | |
- 이전 측정(pre-parallel)의 World Engine $0.80에도 번들 문제가 일부 섞여 있었음 (원인 미분리)

## 2026-11-01 개선 ④ — Maven(+WAR) 지원, Boot 아닌/지원 종료 라인 대응

### 변경 (`prototype/buildtool.py`로 Gradle·Maven 차이를 한 곳에)
- `pom.xml`이면 Maven: `./mvnw`(없으면 `mvn`) `package -DskipTests`, `dependency:tree` 출력을 **Gradle 형식으로 변환**해서 기존 분석·규칙·에이전트를 그대로 사용 (test 스코프 제외)
- 산출물: Boot jar(`BOOT-INF/lib`)와 **WAR(`WEB-INF/lib`)** 모두 지원 — 전자정부 프레임워크(Boot 아님, WAR) 대비
- Spring Boot 버전: Gradle 플러그인 / Maven parent(`spring-boot-starter-parent`) / `spring-boot-dependencies` import에서 감지. Boot가 아니면 BOM 계산 없이 직접 적은 버전 기준으로 조치
- 직접 적은 버전: Gradle 문자열 / pom `<dependency><version>`(`${property}` 해석)
- pom.xml 앞 공백·BOM 때문에 XML 파싱 실패하던 문제 수정 (개인 서비스 A의 pom이 탭으로 시작)
- `--no-llm`에서 kb 규칙이 빠져 있던 버그 수정 (기본 규칙만 돌고 있었음)
- 리포트: **버전 라인 한계** 경고 추가 — 현재 major.minor 라인에 수정 버전이 없는 실행 패키지가 있으면 표시, Boot가 라인의 마지막 패치면 그 사실도 명시

### 외부 레포 빌드는 권한 분류기에서 차단됨
- spring-petclinic, egovframe-web-sample(전자정부 공식 샘플, WAR)을 clone해 빌드하려 했으나 "외부 코드 실행"으로 차단 — 타당한 제한이라 우회하지 않음
- Maven 빌드는 pom의 플러그인 코드를 실행하므로, 외부 레포 분석은 사용자가 직접 빌드를 실행하는 방식으로만 진행

### Evidence — 개인 서비스 A (Maven, Spring Boot 2.7 라인) — `git archive`로 복사해 분석
- Gradle 회귀 확인: Team3 규칙만 실행 결과 동일 (101건, Boot 패치 후 30건)
- 개인 서비스 A: SBOM 115개, **취약점 194건 / 36패키지**, Boot 2.7.18 = 2.7 라인의 마지막 패치 → Boot 패치로 해결 0건
- 실행 패키지 22개(109건)는 현재 라인에 수정 버전 없음 → "버전 라인 한계" 경고
- **처음으로 KEV 등재 취약점 발견**: KEV에 등재된 Tomcat 취약점 1건 (EPSS 0.99 이상) → 프레임워크 핵심 규칙(B) + KEV → P1. Tomcat 같은 라인 안의 패치로 해결 가능
  - 이 CVE는 특정 조건에서만 공격 가능한 것으로 알려져 있음(정확한 조건은 공식 공지로 재확인 필요) — 현재 시스템은 CVE 조건을 보지 않고 보수적으로 P1. CVE 단위 조건 분석은 본선 확장 후보
- 그 밖 고위험: snakeyaml 1.30 CVE-2022-1471(EPSS 0.995), Tomcat 경로 탐색 CVE-2025-55752(EPSS 0.64)
- 판정: 규칙 A 13 · 규칙 B 6(그중 프레임워크 핵심 5) · 에이전트 B 16 · 에이전트 A 1, 검증 실패 0. LLM 24회, **$0.67, 60초**
- 라벨은 만들지 않았음 → 정확도 수치 없음 (대응 범위 시연용)

## 2026-11-01 전자정부 프레임워크 공식 샘플(WAR) 검증 — 사용자가 직접 빌드

### 진행 방식
- `egovframe-web-sample`(eGovFramework 공식, main 9dc46fd, Maven, **Boot 아님, WAR**)은 외부 코드 실행이라 **사용자가 Claude Code에서 직접** `mvn -DskipTests package`와 `mvn dependency:tree -DoutputFile=tree.txt` 실행 (1차는 일반 터미널에서 실행해 결과물 없음 → 2차 성공, BUILD SUCCESS 34.8초)
- 이 도구는 `--deptree-file`로 사용자가 만든 트리를 받아 **WAR와 트리를 읽기만** 함 (빌드 도구 실행 없음)

### 발견·수정한 문제 2개
1. **Maven 버전 조정 표시**: spring-core가 트리에서 `spring-test`(test) 아래에 `compile` 범위로 표시됨 → test 줄을 지우면서 자식이 바로 윗줄(lombok)에 잘못 붙음 (변환기 버그) → 이런 항목은 가상 부모 `maven-mediated:scope-promoted-path-unknown`(경로 불명) 아래로 옮김. provided 범위도 test처럼 제외(WAR에 안 들어감)
2. **shaded 라이브러리**: `ognl:ognl 3.4.4`가 트리에도 없고 별도 jar도 없음 → `mybatis-3.5.19.jar` 안에 통째로 포함(shaded)된 것. 트리에 없는 패키지는 WAR/jar 안의 jar에서 `META-INF/maven/<group>/<artifact>/`를 찾아 **포함한 jar**를 기록(`embedded_in`) → 에이전트 근거와 리포트에 표시

### Evidence
- WAR 45MB, WEB-INF/lib jar 66개, SBOM 76개, 취약점 39건 / 9패키지. Boot 아님 → BOM 계산 없이 조치 계산(전부 조치 4, 그중 3개 라인 전환 필요)
- 판정: 규칙 A 2(spring-web, spring-webmvc), 에이전트 7(전부 B), 검증 실패 0. LLM 18회, **$0.44, 43초**
- **ognl (shaded)**: 에이전트가 `embedded_in=mybatis-3.5.19.jar` 근거를 보고 **매퍼 XML에서 `<if>/<when>`의 `test` 표현식 사용을 검색** → "MyBatis가 런타임에 OGNL 평가 실행" → B. 패키지 이름 검색으로는 못 찾는 실제 사용 경로를 추론
- commons-configuration2: 소스의 `EgovPropertyService` 사용 → 전자정부 프로퍼티 서비스가 이 라이브러리를 실행 → B
- spring-webflux: 소스·설정에 WebFlux 사용 흔적 없음에도 "비활성화 근거 없음"으로 B (보수적, C일 가능성 있음 — 라벨 없음)
- 판정 이유 1건(spring-expression)이 **영어로 출력** → 프롬프트에 "claim과 fix는 한국어로" 추가
- 라벨은 만들지 않음 → 정확도 수치 없음 (대응 범위 시연용)
