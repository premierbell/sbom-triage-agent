"""네트워크·LLM 없이 도는 핵심 로직 테스트. 실행: python3 -m pytest tests"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "prototype"))

import actions  # noqa: E402
import buildtool  # noqa: E402
import judge  # noqa: E402
import kb  # noqa: E402
import reach  # noqa: E402

GRADLE_TREE = """\
+--- org.springframework.boot:spring-boot-starter-web -> 3.5.16
|    +--- org.springframework.boot:spring-boot-starter-json:3.5.16
|    |    \\--- com.fasterxml.jackson.core:jackson-databind:2.19.2
|    \\--- org.springframework.boot:spring-boot-starter-tomcat:3.5.16
|         \\--- org.apache.tomcat.embed:tomcat-embed-core:10.1.55
+--- software.amazon.awssdk:s3 -> 2.20.26
|    \\--- software.amazon.awssdk:netty-nio-client:2.20.26
|         \\--- io.netty:netty-codec-http:4.1.127.Final
\+--- org.springframework.boot:spring-boot-starter-data-redis -> 3.5.16
|    \\--- io.lettuce:lettuce-core:6.5.5
|         \\--- io.netty:netty-handler:4.1.127.Final
\\--- org.springframework.boot:spring-boot-starter-validation -> 3.5.16
     \\--- org.springframework.boot:spring-boot-starter-json:3.5.16 (*)
"""


def row(package, via, direct=False):
    return {"package": package, "via": via, "direct": direct, "import_files": [], "used_packages": []}


# --- reach: import 파싱 -------------------------------------------------------

def test_import_regex_handles_java_and_kotlin():
    cases = {
        "import a.b.C;": "a.b",
        "import static a.b.C.method;": "a.b",
        "import a.b.*;": "a.b",
        "import a.b.C": "a.b",          # Kotlin: 세미콜론 없음
        "import a.b.C as D": "a.b",     # Kotlin: 별칭
    }
    for line, expected in cases.items():
        found = reach.IMPORT.findall(line)
        assert found, line
        assert reach.import_package(found[0]) == expected, line


def test_parse_deptree_finds_roots_and_direct(tmp_path):
    tree = tmp_path / "deptree.txt"
    tree.write_text(GRADLE_TREE)
    roots = reach.parse_deptree(str(tree))
    assert roots["io.netty:netty-codec-http"] == {"software.amazon.awssdk:s3"}
    assert "software.amazon.awssdk:s3" in roots["software.amazon.awssdk:s3"]  # 최상위 = 직접 선언


# --- buildtool: Maven 트리 변환 ----------------------------------------------

def test_maven_tree_drops_test_and_provided_and_reroots_mediated():
    maven = """\
egovframework:egovframe-web:war:5.0.0
+- org.egovframe.rte:egovframe-rte-ptl-mvc:jar:5.0.1:compile
|  \\- org.springframework:spring-webmvc:jar:6.2.11:compile
+- org.projectlombok:lombok:jar:1.18.42:provided
+- org.springframework:spring-test:jar:6.2.11:test
|  \\- org.springframework:spring-core:jar:6.2.11:compile
\\- org.assertj:assertj-core:jar:3.27.7:test
"""
    lines = buildtool.maven_tree_to_gradle(maven).splitlines()
    assert "+--- org.egovframe.rte:egovframe-rte-ptl-mvc:5.0.1" in lines
    assert "|    \\--- org.springframework:spring-webmvc:6.2.11" in lines
    assert not any("lombok" in l or "spring-test" in l or "assertj" in l for l in lines)
    # test 의존성 아래 compile로 표시된 항목은 lombok이 아니라 "경로 불명" 가상 부모 아래로
    i = next(i for i, l in enumerate(lines) if "spring-core" in l)
    assert buildtool.MEDIATED_ROOT in lines[i - 1]


# --- actions: 수정 버전 선택 --------------------------------------------------

def test_required_fix_prefers_same_line():
    assert actions.required_fix("10.1.49", "11.0.25, 10.1.58, 9.0.121") == "10.1.58"
    assert actions.required_fix("6.2.14", "7.0.9") == "7.0.9"           # 같은 라인에 없으면 다음 라인
    assert actions.required_fix("2.21.7", "2.21.5, 2.18.9") is None     # 이미 수정 버전 이상


def test_plan_without_boot_uses_pins_and_flags_cross_line():
    vulns = [
        {"PkgName": "org.redisson:redisson", "InstalledVersion": "3.17.0", "FixedVersion": "3.22.0",
         "VulnerabilityID": "CVE-1"},
        {"PkgName": "org.springframework:spring-webmvc", "InstalledVersion": "6.2.14", "FixedVersion": "7.0.9",
         "VulnerabilityID": "CVE-2"},
    ]
    rows = [{**row("org.redisson:redisson", ["org.redisson:redisson-spring-boot-starter"]), "version": "3.17.0"},
            {**row("org.springframework:spring-webmvc", ["x:y"]), "version": "6.2.14"}]
    planned, remaining = actions.plan(vulns, rows, None, {"org.redisson:redisson-spring-boot-starter": "3.17.0"})
    assert planned["org.redisson:redisson"]["action"] == 3
    assert planned["org.springframework:spring-webmvc"]["cross_line"] is True
    assert remaining == 2


# --- kb: 규칙 -----------------------------------------------------------------

def make_repo(tmp_path, source="", config=""):
    (tmp_path / "src/main/java").mkdir(parents=True)
    (tmp_path / "src/main/resources").mkdir(parents=True)
    (tmp_path / "src/main/java/App.java").write_text(source)
    (tmp_path / "src/main/resources/application.yml").write_text(config)
    return str(tmp_path)


def test_aws_sync_rule_only_when_every_path_is_netty_nio_client(tmp_path):
    repo = make_repo(tmp_path, source="S3Client client = S3Client.create();")
    lines = GRADLE_TREE.splitlines()
    assert kb.aws_sync_only_netty(row("io.netty:netty-codec-http", ["software.amazon.awssdk:s3"]), lines, repo)["category"] == "C"
    # Redis(Lettuce) 경로가 있으면 규칙을 적용하지 않는다
    assert kb.aws_sync_only_netty(row("io.netty:netty-handler", ["x"]), lines, repo) is None


def test_aws_sync_rule_backs_off_on_async_usage(tmp_path):
    repo = make_repo(tmp_path, source="S3AsyncClient c = S3AsyncClient.create();")
    assert kb.aws_sync_only_netty(row("io.netty:netty-codec-http", []), GRADLE_TREE.splitlines(), repo) is None


def test_springdoc_rule_reads_disabled_flag(tmp_path):
    tree = ["+--- org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.13",
            "|    \\--- org.apache.commons:commons-lang3:3.17.0",
            "\\--- org.springframework.boot:spring-boot-starter-web -> 3.5.6 (*)"]
    off = make_repo(tmp_path / "off", config="springdoc:\n  api-docs:\n    enabled: false\n")
    on = make_repo(tmp_path / "on", config="springdoc:\n  swagger-ui:\n    path: /swagger-ui.html\n")
    pkg = row("org.apache.commons:commons-lang3", [])
    assert kb.springdoc_disabled(pkg, tree, off)["category"] == "C"
    assert kb.springdoc_disabled(pkg, tree, on)["category"] == "B"


def test_framework_core_rule_marks_tomcat_running(tmp_path):
    repo = make_repo(tmp_path)
    result = kb.framework_core(row("org.apache.tomcat.embed:tomcat-embed-core", []), GRADLE_TREE.splitlines(), repo)
    assert result["category"] == "B"


# --- judge: 근거 인용 검증 -----------------------------------------------------

def test_validate_rejects_bad_citations_and_unsafe_c():
    evidence = {"E1": {"cve": "CVE-2024-1"}, "T1": {"tool": "build_file"}}
    kinds = {"T1": "build_file"}
    result = {"category": "C", "reasons": [
        {"claim": "CVE-2099-9 때문", "evidence": ["E1"]},
        {"claim": "근거 없음", "evidence": ["E9"]},
    ]}
    problems = judge.validate(result, evidence, kinds, {"direct": True})
    text = " ".join(problems)
    assert "존재하지 않는 근거" in text
    assert "근거에 없는 취약점 ID" in text
    assert "검색 근거 미인용" in text
    assert "직접 선언한 의존성을 C로" in text


# --- conditions: CVE 공격 조건 검증 ---------------------------------------------

import conditions  # noqa: E402

DESC = ("If all of the following were true, RCE: - writes enabled for the default servlet (disabled by default) "
        "- support for partial PUT (enabled by default). Requests are blocked when the firewall is in use.")


def cond(quote, status, evidence):
    return {"quote": quote, "status": status, "evidence": evidence}


def test_conditions_not_exploitable_needs_quote_and_search_evidence():
    result = {"scenarios": [{"name": "RCE", "conditions": [
        cond("writes enabled for the default servlet", "not_met", ["T1: 설정 검색 결과 없음"]),  # 설명 붙은 ID도 인정
        cond("support for partial PUT", "met", ["T2"]),
    ]}], "verdict": "not_exploitable"}
    problems = conditions.validate(result, DESC, {"T1": "search_config", "T2": "search_source"})
    assert problems == [] and result["verdict"] == "not_exploitable"


def test_conditions_rejects_invented_quote_and_unsupported_not_met():
    invented = {"scenarios": [{"name": "x", "conditions": [cond("attacker controls the JVM", "not_met", ["T1"])]}],
                "verdict": "not_exploitable"}
    conditions.validate(invented, DESC, {"T1": "search_config"})
    assert invented["verdict"] == "unknown"  # 원문에 없는 인용은 무효

    unsupported = {"scenarios": [{"name": "x", "conditions": [cond("support for partial PUT", "not_met", [])]}],
                   "verdict": "not_exploitable"}
    conditions.validate(unsupported, DESC, {})
    assert unsupported["verdict"] == "unknown"  # 검색 근거 없는 미충족은 무효


def test_conditions_every_scenario_must_be_blocked_and_mitigations_ignored():
    result = {"scenarios": [
        {"name": "A", "conditions": [cond("writes enabled for the default servlet", "not_met", ["T1"])]},
        {"name": "B", "conditions": [cond("support for partial PUT", "met", ["T1"])]},
    ], "mitigations": [cond("the firewall is in use", "not_met", ["T1"])], "verdict": "not_exploitable"}
    conditions.validate(result, DESC, {"T1": "search_config"})
    assert result["verdict"] == "exploitable"  # 시나리오 B가 막히지 않았고, 완화 요인은 판정에 쓰지 않는다


def test_springdoc_rule_sees_paths_hidden_by_gradle_elision(tmp_path):
    """실제로 발견한 함정: logback이 트리 문자열에선 springdoc 아래에만 보이지만, starter-web 쪽 경로는 (*)로 접혀 있었다.
    Swagger를 끈 서비스에서 logback을 '실행 안 됨'으로 내리면 위험한 오판이 된다."""
    tree = [
        "+--- org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.13",
        "|    \\--- org.springframework.boot:spring-boot-starter:3.5.6",
        "|         \\--- org.springframework.boot:spring-boot-starter-logging:3.5.6",
        "|              \\--- ch.qos.logback:logback-core:1.5.18",
        "\\--- org.springframework.boot:spring-boot-starter-web -> 3.5.6",
        "     \\--- org.springframework.boot:spring-boot-starter:3.5.6 (*)",
    ]
    repo = make_repo(tmp_path, config="springdoc:\n  api-docs:\n    enabled: false\n")
    assert kb.all_through(tree, "ch.qos.logback:logback-core", "org.springdoc:") is False
    assert kb.springdoc_disabled(row("ch.qos.logback:logback-core", []), tree, repo) is None


def test_c_rules_off_for_maven_trees_without_elision_markers(tmp_path):
    """Maven 트리는 중복을 지워서 다른 경로를 확인할 수 없으므로 '실행 안 됨' 규칙을 적용하지 않는다."""
    tree = ["+--- org.springframework.kafka:spring-kafka:3.3.16",
            "|    \\--- org.apache.kafka:kafka-clients:3.9.2",
            "|         \\--- org.xerial.snappy:snappy-java:1.1.10.7"]
    repo = make_repo(tmp_path)
    assert kb.kafka_uncompressed_codec(row("org.xerial.snappy:snappy-java", []), tree, repo) is None
