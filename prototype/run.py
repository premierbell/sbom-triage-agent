"""레포 하나를 SBOM 생성부터 HTML 리포트까지 한 번에 분석한다.

usage: OPENAI_API_KEY=... run.py <gradle_module_dir> [--name NAME] [--model gpt-5.5] [--skip-build] [--no-llm]
결과: runs/<NAME>/ 아래 sbom.cdx.json, trivy.json, deptree.txt, summary.json, report.html
"""
import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import actions  # noqa: E402
import buildtool  # noqa: E402
import enrich  # noqa: E402
import judge  # noqa: E402
import kb  # noqa: E402
import reach  # noqa: E402
import report  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BOOT_METADATA = "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot/maven-metadata.xml"


def step(name):
    print(f"[{time.strftime('%H:%M:%S')}] {name}", flush=True)


def sh(cmd, cwd=None, out=None):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"실패: {' '.join(cmd)}\n{result.stderr[-2000:]}")
    if out:
        pathlib.Path(out).write_text(result.stdout)
    return result.stdout


def boot_versions(module, tool):
    """현재 Spring Boot 버전과 같은 minor 라인의 최신 패치 버전. Boot 프로젝트가 아니면 (None, None)."""
    current = buildtool.boot_version(module, tool)
    if not current:
        return None, None
    line = ".".join(current.split(".")[:2])
    versions = re.findall(rf"<version>({re.escape(line)}\.\d+)</version>", sh(["curl", "-sf", BOOT_METADATA]))
    latest = max(versions, key=lambda v: int(v.rsplit(".", 1)[1]), default=current)
    return current, latest


def kev_file():
    """CISA KEV 목록. 하루 지난 캐시는 새로 받는다."""
    cache = ROOT / "runs" / "_cache" / "kev.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists() or time.time() - cache.stat().st_mtime > 86400:
        sh(["curl", "-sf", "-o", str(cache), KEV_URL])
    return cache


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module")
    ap.add_argument("--name")
    ap.add_argument("--model", default="gpt-5.5")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--no-llm", action="store_true", help="규칙 판정만 하고 LLM 판단은 건너뜀")
    ap.add_argument("--build-tool", choices=["gradle", "maven"], help="둘 다 있을 때 지정 (기본: Gradle 우선)")
    ap.add_argument("--deptree-file", help="미리 만든 의존성 트리 파일 (Maven이면 mvn dependency:tree 출력). "
                                           "외부 레포처럼 이 도구가 빌드 도구를 직접 실행하면 안 될 때 사용")
    args = ap.parse_args()

    module = pathlib.Path(args.module).resolve()
    name = args.name or module.name
    out = ROOT / "runs" / name
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()

    tool = buildtool.detect(module, args.build_tool)
    if not args.skip_build:
        step(f"빌드 ({tool}, 테스트 제외)")
        buildtool.build(module, tool)
    jar = buildtool.artifact(module, tool)

    if args.deptree_file:
        step(f"의존성 트리 (제공된 파일 사용: {args.deptree_file})")
        raw = pathlib.Path(args.deptree_file).read_text()
        (out / "deptree.txt").write_text(buildtool.maven_tree_to_gradle(raw) if tool == "maven" else raw)
    else:
        step(f"의존성 트리 ({tool})")
        buildtool.deptree(module, tool, out / "deptree.txt")

    step("SBOM 생성 (syft, CycloneDX)")
    sh(["syft", str(jar), "-o", f"cyclonedx-json={out / 'sbom.cdx.json'}", "-q"])
    components = len(json.loads((out / "sbom.cdx.json").read_text()).get("components", []))

    step("취약점 대조 (trivy)")
    sh(["trivy", "sbom", str(out / "sbom.cdx.json"), "-f", "json", "-o", str(out / "trivy.json"), "-q"])

    step("EPSS·KEV 결합")
    vulns = enrich.enrich(str(out / "trivy.json"), str(kev_file()))

    step("도입 경로·소스 사용 분석")
    rows = reach.analyze(vulns, str(out / "deptree.txt"), str(jar), str(module / "src" / "main"))
    reach_rows = {r["package"]: r for r in rows}

    step("전체 구성요소 사용 인덱스 (역조회용)")
    sbom = json.loads((out / "sbom.cdx.json").read_text())
    pseudo = [{"PkgName": f'{c["group"]}:{c["name"]}', "InstalledVersion": c.get("version", ""), "Severity": "UNKNOWN"}
              for c in sbom.get("components", []) if c.get("group") and c.get("type") == "library"]
    component_usage = reach.analyze(pseudo, str(out / "deptree.txt"), str(jar), str(module / "src" / "main"))

    current, latest = boot_versions(module, tool)
    os.environ["BOOT"] = f"{current} (같은 라인 최신 패치 {latest})" if current else "Spring Boot 아님"
    os.environ["PROMPT"] = "v2"
    usage = {"calls": 0, "input": 0, "cached": 0, "output": 0}
    if args.no_llm:
        step("판정 (규칙만)")
        deptree_lines = (out / "deptree.txt").read_text().splitlines()
        results = {}
        for pkg, row in reach_rows.items():
            decided = (judge.rule_decision(row, [v for v in vulns if v["PkgName"] == pkg])
                       or kb.decide(row, deptree_lines, str(module)))
            results[pkg] = {"result": decided or {"category": "?", "priority": "-", "decided_by": "미판정(LLM 생략)",
                                                  "reasons": []}, "problems": [], "trace": []}
    else:
        if "OPENAI_API_KEY" not in os.environ:
            raise SystemExit("OPENAI_API_KEY가 필요합니다 (--no-llm으로 규칙 판정만 할 수도 있음)")
        step(f"판정 (규칙 + 에이전트 {args.model})")
        results = judge.main_v3(vulns, reach_rows, open(out / "deptree.txt").read().splitlines(),
                                str(module), args.model, usage)
    usage["usd"] = round(judge.cost(args.model, usage), 4) if usage["calls"] else 0.0

    step("조치 계산 (Spring Boot BOM 대조)")
    planned, boot_remaining = actions.plan(vulns, rows, latest, buildtool.pinned_versions(module, tool))

    summary = {
        "name": name, "module": str(module), "jar": jar.name, "build_tool": tool,
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "model": None if args.no_llm else args.model,
        "boot": {"current": current, "latest_patch": latest},
        "sbom_components": components, "component_usage": component_usage, "vulns": vulns, "packages": rows,
        "results": results, "actions": planned, "boot_remaining": boot_remaining, "usage": usage, "elapsed_sec": round(time.time() - started),
    }
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1))
    step("리포트 생성")
    (out / "report.html").write_text(report.render(summary))
    print(f"완료: {out / 'report.html'}  (LLM 호출 {usage['calls']}회, ${usage['usd']}, {summary['elapsed_sec']}초)")


if __name__ == "__main__":
    main()
