"""취약 패키지마다 (1) 어느 직접 의존성을 통해 들어왔는지 (2) 내 소스가 import하는지 붙인다.

usage: reach.py <enriched.json> <deptree.txt> <boot.jar> <src_dir>
"""
import collections
import json
import pathlib
import re
import sys
import zipfile

LINE = re.compile(r"^([| ]*)[+\\]--- (\S+)(?: -> (\S+))?")


def parse_deptree(path):
    """artifact(group:name) -> 그 artifact로 이어지는 직접 의존성(최상위) 집합."""
    roots = collections.defaultdict(set)
    stack = []
    for line in open(path):
        m = LINE.match(line)
        if not m:
            continue
        depth = len(m.group(1)) // 5
        ga = ":".join(m.group(2).split(":")[:2])
        stack = stack[:depth] + [ga]
        roots[ga].add(stack[0])
    return roots


# Java(`import a.b.C;`)와 Kotlin(`import a.b.C`, `import a.b.C as D`) 둘 다
IMPORT = re.compile(r"^import (?:static )?([\w.]+?)(?:\.\*)?(?:\s+as\s+\w+)?;?[ \t]*$", re.M)
SOURCE_SUFFIXES = (".java", ".kt")


def java_packages(jar_path, artifact, version):
    """Boot jar(BOOT-INF/lib) 또는 WAR(WEB-INF/lib) 안의 <artifact>-<version>.jar에 든 클래스들의 정확한 패키지 집합."""
    with zipfile.ZipFile(jar_path) as boot:
        names = set(boot.namelist())
        name = next((f"{d}/{artifact}-{version}.jar" for d in ("BOOT-INF/lib", "WEB-INF/lib")
                     if f"{d}/{artifact}-{version}.jar" in names), None)
        if not name:
            return set()
        with boot.open(name) as inner, zipfile.ZipFile(inner) as lib:
            return {
                entry.rsplit("/", 1)[0].replace("/", ".")
                for entry in lib.namelist()
                if entry.endswith(".class") and "/" in entry and not entry.startswith("META-INF")
            }


def import_package(name):
    """'a.b.C', 'a.b.C.method', 'a.b'(와일드카드) -> 패키지 'a.b'. 대문자로 시작하는 첫 세그먼트 앞까지."""
    parts = name.split(".")
    for i, p in enumerate(parts):
        if p[:1].isupper():
            return ".".join(parts[:i])
    return name


def source_imports(src_dir):
    """파일 -> 그 파일이 import하는 패키지 집합."""
    result = {}
    for f in pathlib.Path(src_dir).rglob("*"):
        if f.suffix not in SOURCE_SUFFIXES:
            continue
        result[f] = {import_package(m) for m in IMPORT.findall(f.read_text(errors="ignore"))}
    return result


def importing_files(imports, pkgs):
    return {f for f, used in imports.items() if used & pkgs}


def embedded_in(jar_path, group, artifact):
    """트리에 없는 라이브러리가 다른 jar 안에 통째로 포함(shaded)돼 있으면 그 jar 이름."""
    marker = f"META-INF/maven/{group}/{artifact}/"
    with zipfile.ZipFile(jar_path) as outer:
        for name in outer.namelist():
            if not (name.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")) and name.endswith(".jar")):
                continue
            with outer.open(name) as inner, zipfile.ZipFile(inner) as lib:
                if any(n.startswith(marker) for n in lib.namelist()):
                    return name.rsplit("/", 1)[1]
    return None


def analyze(vulns, deptree, jar, src_dir):
    """취약 패키지별 도입 경로·직접 선언 여부·소스 import 현황."""
    roots = parse_deptree(deptree)
    imports = source_imports(src_dir)
    by_pkg = collections.defaultdict(list)
    for v in vulns:
        by_pkg[(v["PkgName"], v["InstalledVersion"])].append(v)

    rows = []
    for (ga, ver), vs in by_pkg.items():
        pkgs = java_packages(jar, ga.split(":")[1], ver)
        files = importing_files(imports, pkgs)
        used_pkgs = sorted(set().union(*(imports[f] for f in files)) & pkgs) if files else []
        rows.append({
            "package": ga, "version": ver, "vulns": len(vs),
            "crit_high": sum(v["Severity"] in ("CRITICAL", "HIGH") for v in vs),
            "direct": ga in roots.get(ga, set()),
            "via": sorted(roots.get(ga, [])),
            "java_package_count": len(pkgs),
            "used_packages": used_pkgs,
            "import_files": sorted(str(f.relative_to(src_dir)) for f in files),
            "embedded_in": None if (pkgs or ga in roots) else embedded_in(jar, *ga.split(":", 1)),
        })
    rows.sort(key=lambda r: (-len(r["import_files"]), -r["vulns"]))
    return rows


def main(enriched, deptree, jar, src_dir):
    rows = analyze(json.load(open(enriched)), deptree, jar, src_dir)
    for r in rows:
        mark = "DIRECT" if r["direct"] else "via " + ",".join(x.split(":")[1] for x in r["via"])
        print(f"{r['package'].split(':')[1]:28} {r['vulns']:>3}건 (C+H {r['crit_high']:>2}) "
              f"import {len(r['import_files']):>3}파일 | {mark}"
              + ("" if r["java_package_count"] else "  ※jar에서 클래스 못 찾음"))
        if r["used_packages"]:
            print(f"{'':28} └ 사용 패키지: {', '.join(r['used_packages'])}")
    used = [r for r in rows if r["import_files"]]
    print(f"\n취약 패키지 {len(rows)}개 중 소스에서 import {len(used)}개 "
          f"/ 취약점 {sum(r['vulns'] for r in rows)}건 중 {sum(r['vulns'] for r in used)}건")
    json.dump(rows, open(enriched.replace(".enriched.json", ".reach.json"), "w"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:5])
