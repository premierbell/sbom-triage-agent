"""반복되는 판단 패턴을 LLM 대신 결정론적 규칙으로 처리하는 지식베이스.

규칙은 보수적으로: C(실행 안 됨) 규칙은 조건이 하나라도 애매하면 None을 돌려 에이전트에게 넘긴다.
B(실행됨) 규칙은 틀려도 안전한 방향이라 프레임워크가 항상 싣는 경로면 바로 판정한다.
"""
import pathlib
import re

import judge

# 비동기 AWS SDK를 쓴다는 흔적 — 하나라도 있으면 netty-nio-client가 실행될 수 있다
AWS_ASYNC = r"AsyncClient|NettyNioAsyncHttpClient|S3TransferManager|CrtAsyncHttpClient|S3CrtAsyncClient"
KAFKA_CODECS = {"org.lz4:lz4-java", "at.yawk.lz4:lz4-java", "org.xerial.snappy:snappy-java", "com.github.luben:zstd-jni"}
KAFKA_COMPRESSION = r"compression[._-]?type|compressionType|COMPRESSION_TYPE"


TREE_LINE = re.compile(r"^([| ]*)[+\\]--- (\S+)")


def chains(deptree_lines, package):
    return judge.dependency_path(deptree_lines, package)


def graph(deptree_lines):
    """Gradle 트리 → (루트 집합, 자식 그래프). `(*)`로 접힌 중복 노드도 처음 펼쳐진 곳의 자식을 공유하게 된다."""
    roots, children, stack = set(), {}, []
    for line in deptree_lines:
        m = TREE_LINE.match(line)
        if not m:
            continue
        depth = len(m.group(1)) // 5
        node = ":".join(m.group(2).split(":")[:2])
        stack = stack[:depth] + [node]
        if depth == 0:
            roots.add(node)
        else:
            children.setdefault(stack[depth - 1], set()).add(node)
    return roots, children


def can_verify_all_paths(deptree_lines):
    """Gradle 트리는 중복을 `(*)`로 표시해 모든 경로를 복원할 수 있다. Maven 트리는 중복을 아예 지워서 불가."""
    return any("(*)" in line for line in deptree_lines)


def all_through(deptree_lines, package, carrier_prefix):
    """루트에서 package까지 가는 모든 경로가 carrier_prefix로 시작하는 노드를 거치는가 (거치지 않는 경로가 하나라도 있으면 False)."""
    roots, children = graph(deptree_lines)
    blocked = lambda n: n.startswith(carrier_prefix)  # noqa: E731
    seen, todo = set(), [r for r in roots if not blocked(r)]
    while todo:
        node = todo.pop()
        if node == package:
            return False
        if node in seen:
            continue
        seen.add(node)
        todo.extend(c for c in children.get(node, ()) if not blocked(c))
    # carrier 없이는 도달 불가. 단 package가 트리에 아예 없으면 판단하지 않는다
    return any(package in kids for kids in children.values()) or package in roots


def aws_sync_only_netty(row, deptree_lines, repo):
    if not row["package"].startswith("io.netty:"):
        return None
    if not can_verify_all_paths(deptree_lines) or \
            not all_through(deptree_lines, row["package"], "software.amazon.awssdk:netty-nio-client"):
        return None
    paths = chains(deptree_lines, row["package"])
    async_hits = judge.grep(AWS_ASYNC, f"{repo}/src/main", 12, include=("*.java", "*.kt"))
    if async_hits:
        return None
    sync_hits = judge.grep(r"S3Client|S3Presigner|DynamoDbClient|SqsClient|SnsClient", f"{repo}/src/main", 5,
                           include=("*.java", "*.kt"))
    return {
        "category": "C", "decided_by": "rule:kb-aws-sync",
        "reasons": [
            {"claim": "이 패키지로 가는 모든 의존성 경로가 AWS SDK의 netty-nio-client를 거친다 "
                      "(netty-nio-client는 비동기 클라이언트 전용 HTTP 구현)", "evidence": ["deptree"]},
            {"claim": f"소스에 비동기 SDK 사용 흔적({AWS_ASYNC})이 없고 동기 클라이언트만 사용한다", "evidence": ["src-grep"]},
        ],
        "evidence": {"deptree": paths, "src-grep": {"async": async_hits, "sync": sync_hits}},
    }


def kafka_uncompressed_codec(row, deptree_lines, repo):
    if row["package"] not in KAFKA_CODECS:
        return None
    if not can_verify_all_paths(deptree_lines) or \
            not all_through(deptree_lines, row["package"], "org.apache.kafka:kafka-clients"):
        return None
    paths = chains(deptree_lines, row["package"])
    config_hits = judge.grep(KAFKA_COMPRESSION, f"{repo}/src/main/resources", 12, include=judge.CONFIG_FILES)
    source_hits = judge.grep(KAFKA_COMPRESSION, f"{repo}/src/main", 12, include=("*.java", "*.kt"))
    if config_hits or source_hits:
        return None
    return {
        "category": "C", "decided_by": "rule:kb-kafka-codec",
        "reasons": [
            {"claim": "이 압축 코덱으로 가는 모든 의존성 경로가 kafka-clients를 거친다", "evidence": ["deptree"]},
            {"claim": "설정·소스에 Kafka 압축 설정이 없어 이 서비스의 프로듀서는 기본값(compression.type=none)으로 "
                      "압축하지 않는다. 단, 다른 서비스가 압축해 보낸 토픽을 소비하면 해제 경로가 실행될 수 있으므로 "
                      "토픽 생산자를 확인할 것", "evidence": ["config-grep"]},
        ],
        "evidence": {"deptree": paths, "config-grep": {"config": config_hits, "source": source_hits}},
    }


# 이 경로로 들어왔으면 Spring Boot 앱에서 항상 실행되는 라이브러리 → B
FRAMEWORK_CORE = [
    ("org.apache.tomcat.embed:tomcat-embed-core", "spring-boot-starter-tomcat", "내장 서블릿 컨테이너로 매 HTTP 요청을 처리"),
    ("com.fasterxml.jackson.core:jackson-databind", "spring-boot-starter-json", "HTTP 메시지 변환(JSON 직렬화)에 매 요청 사용"),
    ("com.fasterxml.jackson.core:jackson-core", "spring-boot-starter-json", "HTTP 메시지 변환(JSON 직렬화)에 매 요청 사용"),
    ("tools.jackson.core:jackson-databind", "spring-boot-starter-jackson", "HTTP 메시지 변환(JSON 직렬화)에 매 요청 사용"),
    ("tools.jackson.core:jackson-core", "spring-boot-starter-jackson", "HTTP 메시지 변환(JSON 직렬화)에 매 요청 사용"),
    ("ch.qos.logback:logback-core", "spring-boot-starter-logging", "기본 로깅 구현으로 항상 로드"),
    ("ch.qos.logback:logback-classic", "spring-boot-starter-logging", "기본 로깅 구현으로 항상 로드"),
    ("org.springframework:spring-expression", "org.springframework:spring-context", "애플리케이션 컨텍스트가 표현식 평가에 사용"),
]


def framework_core(row, deptree_lines, repo):
    for package, carrier, why in FRAMEWORK_CORE:
        if row["package"] != package:
            continue
        paths = chains(deptree_lines, package)
        through = [p for p in paths if carrier in p]
        if not through:
            return None
        return {
            "category": "B", "decided_by": "rule:kb-framework-core",
            "reasons": [{"claim": f"{carrier} 경로로 들어온 프레임워크 핵심 라이브러리 — {why}", "evidence": ["deptree"]}],
            "evidence": {"deptree": through},
        }
    return None


def config_values(resources):
    """application*.yml/yaml/properties → {파일명: {점으로 이은 키: 값}}. 단순 들여쓰기 YAML만 다룬다."""
    out = {}
    for f in sorted(pathlib.Path(resources).glob("application*")):
        values = {}
        if f.suffix == ".properties":
            for line in f.read_text(errors="ignore").splitlines():
                m = re.match(r"\s*([\w.\-]+)\s*[=:]\s*(.*?)\s*$", line)
                if m and not line.lstrip().startswith("#"):
                    values[m.group(1)] = m.group(2)
        elif f.suffix in (".yml", ".yaml"):
            stack = []
            for line in f.read_text(errors="ignore").splitlines():
                m = re.match(r"^(\s*)([\w.\-]+):\s*(.*?)\s*(?:#.*)?$", line)
                if not m or line.lstrip().startswith("#"):
                    continue
                indent, key, value = len(m.group(1)), m.group(2), m.group(3).strip("'\"")
                stack = [(i, k) for i, k in stack if i < indent] + [(indent, key)]
                if value:
                    values[".".join(k for _, k in stack)] = value
        out[f.name] = values
    return out


def springdoc_disabled(row, deptree_lines, repo):
    paths = chains(deptree_lines, row["package"])
    if not paths or not all_through(deptree_lines, row["package"], "org.springdoc:"):
        return None
    c_allowed = can_verify_all_paths(deptree_lines)  # Maven 트리면 다른 경로를 확인할 수 없어 C로 내리지 않는다
    configs = config_values(f"{repo}/src/main/resources")
    disabled = [name for name, values in configs.items()
                if values.get("springdoc.api-docs.enabled", "").lower() == "false"]
    effective = [n for n in disabled if n in ("application.yml", "application.yaml", "application.properties") or "prod" in n]
    evidence = {"deptree": paths, "config": {n: {k: v for k, v in vals.items() if k.startswith("springdoc")}
                                             for n, vals in configs.items()}}
    if effective and not c_allowed:
        return None
    if effective:
        return {
            "category": "C", "decided_by": "rule:kb-springdoc",
            "reasons": [
                {"claim": "이 패키지로 가는 모든 의존성 경로가 springdoc(OpenAPI 문서화)을 거친다", "evidence": ["deptree"]},
                {"claim": f"{', '.join(effective)}에서 springdoc.api-docs.enabled=false — 운영에서 문서 생성 경로가 꺼져 있다",
                 "evidence": ["config"]},
            ],
            "evidence": evidence,
        }
    return {
        "category": "B", "decided_by": "rule:kb-springdoc",
        "reasons": [
            {"claim": "이 패키지로 가는 모든 의존성 경로가 springdoc(OpenAPI 문서화)을 거친다", "evidence": ["deptree"]},
            {"claim": "기본 설정·운영 설정에 springdoc 비활성화가 없어 기본값(활성)으로 문서 생성 경로가 실행된다"
                      + (f" (비활성화는 {', '.join(disabled)}에만 있음)" if disabled else ""), "evidence": ["config"]},
        ],
        "evidence": evidence,
    }


RULES = [aws_sync_only_netty, kafka_uncompressed_codec, springdoc_disabled, framework_core]


def decide(row, deptree_lines, repo):
    for rule in RULES:
        result = rule(row, deptree_lines, repo)
        if result:
            return result
    return None
