"""Gradle·Maven 차이를 한 곳에 모은다. 나머지 단계는 Gradle 형식 의존성 트리와 jar/war 하나만 받는다."""
import pathlib
import re
import subprocess
import xml.etree.ElementTree as ET

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
GRADLE_FILES = ("build.gradle.kts", "build.gradle")
MAVEN_LINE = re.compile(r"^([| ]*)([+\\])- (\S+)")


def sh(cmd, cwd=None):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"실패: {' '.join(cmd)}\n{(result.stdout + result.stderr)[-2000:]}")
    return result.stdout


def detect(module, prefer=None):
    has_gradle = any((module / f).exists() for f in GRADLE_FILES)
    has_maven = (module / "pom.xml").exists()
    if prefer:
        return prefer
    if has_gradle:
        return "gradle"
    if has_maven:
        return "maven"
    raise SystemExit("build.gradle(.kts)도 pom.xml도 없습니다")


def build_file(module, tool):
    if tool == "maven":
        return module / "pom.xml"
    return next(module / f for f in GRADLE_FILES if (module / f).exists())


def maven_cmd(module):
    return ["./mvnw"] if (module / "mvnw").exists() else ["mvn"]


def build(module, tool):
    if tool == "maven":
        sh(maven_cmd(module) + ["-q", "-DskipTests", "package"], cwd=module)
    else:
        sh(["./gradlew", "bootJar", "-x", "test", "-q"], cwd=module)


MEDIATED_ROOT = "maven-mediated:scope-promoted-path-unknown:0"


def maven_tree_to_gradle(text):
    """`mvn dependency:tree` 출력(g:a:type[:classifier]:v:scope)을 Gradle 형식(g:a:v, 들여쓰기 5칸)으로 바꾼다.

    test·provided 범위는 지운다(실행 산출물에 들어가지 않음). 다만 Maven이 버전 조정으로 test 의존성 아래에 compile/runtime 범위로 표시한 항목은
    실제 실행 클래스패스에 들어가므로 남기되, 실제 도입 경로를 알 수 없어 가상 부모(MEDIATED_ROOT) 아래로 옮긴다.
    """
    out, dropped_at = [], None
    for line in text.splitlines():
        m = MAVEN_LINE.match(line)
        if not m:
            continue
        parts = m.group(3).split(":")
        if len(parts) < 5:
            continue
        depth = len(m.group(1)) // 3
        if dropped_at is not None and depth <= dropped_at:
            dropped_at = None
        if parts[-1] in ("test", "provided"):
            if dropped_at is None:
                dropped_at = depth
            continue
        coord = f"{parts[0]}:{parts[1]}:{parts[-2]}"
        if dropped_at is not None:
            out.append("+--- " + MEDIATED_ROOT)
            depth = 1 + max(0, depth - dropped_at - 1)
        out.append("|    " * depth + ("+--- " if m.group(2) == "+" else "\\--- ") + coord)
    return "\n".join(out) + "\n"


def deptree(module, tool, out_path):
    if tool == "maven":
        raw = pathlib.Path(out_path).with_suffix(".maven.txt")
        sh(maven_cmd(module) + ["-q", "dependency:tree", f"-DoutputFile={raw.resolve()}"], cwd=module)
        pathlib.Path(out_path).write_text(maven_tree_to_gradle(raw.read_text()))
    else:
        pathlib.Path(out_path).write_text(
            sh(["./gradlew", "dependencies", "--configuration", "runtimeClasspath", "-q"], cwd=module))


def artifact(module, tool):
    """실행 산출물. Boot jar(BOOT-INF/lib) 또는 WAR(WEB-INF/lib)."""
    if tool == "maven":
        found = [p for p in (module / "target").glob("*.[jw]ar")
                 if not p.name.endswith(("-plain.jar", "-sources.jar", "-javadoc.jar"))]
    else:
        found = [p for p in (module / "build" / "libs").glob("*.[jw]ar") if not p.name.endswith("-plain.jar")]
    if not found:
        raise SystemExit("빌드 산출물(jar/war)이 없습니다 (--skip-build 없이 실행하세요)")
    return max(found, key=lambda p: p.stat().st_mtime)


def read_pom(module):
    # 선언부 앞의 공백·BOM 때문에 XML 파싱이 실패하는 pom이 있다
    return ET.fromstring(build_file(module, "maven").read_text().lstrip("\ufeff \t\r\n"))


def pom_properties(root):
    return {p.tag.split("}")[1]: (p.text or "").strip() for p in root.findall("m:properties/*", NS)}


def boot_version(module, tool):
    """build 파일에 적힌 Spring Boot 버전. Boot 프로젝트가 아니면 None."""
    text = build_file(module, tool).read_text()
    if tool == "gradle":
        m = re.search(r"org\.springframework\.boot['\"]?\)?\s+version\s+['\"]([\d.]+)['\"]", text)
        return m.group(1) if m else None
    root = read_pom(module)
    parent = root.find("m:parent", NS)
    if parent is not None and parent.findtext("m:artifactId", "", NS) in ("spring-boot-starter-parent",
                                                                          "spring-boot-dependencies"):
        return parent.findtext("m:version", "", NS)
    props = pom_properties(root)
    for d in root.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
        if d.findtext("m:artifactId", "", NS) == "spring-boot-dependencies":
            v = d.findtext("m:version", "", NS)
            return props.get(v[2:-1], v) if v.startswith("${") else v
    return None


def pinned_versions(module, tool):
    """build 파일에 버전을 직접 적은 의존성 {group:artifact: version}."""
    text = build_file(module, tool).read_text()
    if tool == "gradle":
        return {f"{g}:{a}": v for g, a, v in re.findall(r"['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]", text)}
    root = read_pom(module)
    props = pom_properties(root)
    pins = {}
    for d in root.findall("m:dependencies/m:dependency", NS):
        v = d.findtext("m:version", "", NS)
        if not v:
            continue
        if v.startswith("${"):
            v = props.get(v[2:-1], v)
        pins[f'{d.findtext("m:groupId", "", NS)}:{d.findtext("m:artifactId", "", NS)}'] = v
    return pins
