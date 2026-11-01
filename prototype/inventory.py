"""여러 서비스의 분석 결과(runs/*/summary.json)를 모아 역조회한다.

usage:
  inventory.py --cve CVE-2023-42809              이미 알려진 취약점: 어느 서비스에 있고 실행되는가
  inventory.py --package jackson-databind --fixed 2.21.7
                                                 새 취약점: 이 패키지를 수정 버전 미만으로 쓰는 서비스와 실행 여부
  [--html out.html]                              결과를 HTML로도 저장
"""
import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import judge  # noqa: E402
import kb  # noqa: E402
from actions import vkey  # noqa: E402
from report import CSS, esc  # noqa: E402

RUNS = pathlib.Path(__file__).resolve().parent.parent / "runs"


def load_services():
    services = []
    for p in sorted(RUNS.glob("*/summary.json")):
        s = json.loads(p.read_text())
        if "component_usage" in s:
            services.append(s)
    return services


def usage_status(service, pkg, usage):
    """이미 판정된 결과가 있으면 그것을, 없으면 사용 인덱스로 1차 판단한다."""
    judged = service["results"].get(pkg, {}).get("result")
    if judged and judged.get("category") in ("A", "B", "C"):
        return judged["category"], f'판정 {judged["category"]} ({judged.get("decided_by", "llm")})'
    if usage["import_files"]:
        return "A", f'소스 {len(usage["import_files"])}개 파일이 import'
    if usage["direct"]:
        return "B", "build 파일에 직접 선언 (import 없음)"
    return "?", "전이 의존성, 코드 직접 사용 없음 → 실행 여부는 에이전트 판정 필요"


def lookup_package(services, name, fixed):
    rows = []
    for s in services:
        for u in s["component_usage"]:
            if u["package"] == name or u["package"].split(":")[1] == name:
                vulnerable = fixed is None or vkey(u["version"]) < vkey(fixed)
                cat, why = usage_status(s, u["package"], u)
                rows.append({"service": s["name"], "package": u["package"], "version": u["version"],
                             "vulnerable": vulnerable, "category": cat, "why": why,
                             "path": "직접 선언" if u["direct"] else "via " + ", ".join(v.split(":")[1] for v in u["via"])})
    return rows


def lookup_cve(services, cve):
    rows = []
    for s in services:
        usage = {u["package"]: u for u in s["component_usage"]}
        for v in s["vulns"]:
            if v["VulnerabilityID"] != cve:
                continue
            u = usage.get(v["PkgName"], {"import_files": [], "direct": False, "via": []})
            cat, why = usage_status(s, v["PkgName"], u)
            act = s.get("actions", {}).get(v["PkgName"], {})
            rows.append({"service": s["name"], "package": v["PkgName"], "version": v["InstalledVersion"],
                         "vulnerable": True, "category": cat, "why": why, "fix": act.get("fix", ""),
                         "path": "직접 선언" if u["direct"] else "via " + ", ".join(x.split(":")[1] for x in u["via"])})
    return rows


def judge_unknown(services, rows, query, fixed, title, model):
    """실행 여부가 정해지지 않은 서비스만 그 자리에서 에이전트에게 판단시킨다."""
    by_name = {s["name"]: s for s in services}
    usage = {"calls": 0, "input": 0, "cached": 0, "output": 0}
    os.environ["PROMPT"] = "v2"
    for r in rows:
        if not r["vulnerable"] or r["category"] != "?":
            continue
        s = by_name[r["service"]]
        u = next(x for x in s["component_usage"] if x["package"] == r["package"])
        os.environ["BOOT"] = f'{s["boot"]["current"]} (같은 라인 최신 패치 {s["boot"]["latest_patch"]})'
        vuln = {"VulnerabilityID": query, "Severity": "UNKNOWN", "epss": None, "kev": False,
                "InstalledVersion": r["version"], "FixedVersion": fixed, "Title": title or ""}
        deptree = (RUNS / s["name"] / "deptree.txt").read_text().splitlines()
        ruled = kb.decide(u, deptree, s["module"])
        if ruled:
            r["category"] = ruled["category"]
            r["why"] = f'규칙 {ruled["decided_by"]}: ' + " / ".join(x["claim"] for x in ruled["reasons"])
            continue
        result, problems, _ = judge.judge(model, r["package"], [vuln], u, s["module"], deptree, usage,
                                          tool_budget=8, grep_limit=12)
        r["category"] = result["category"]
        r["why"] = (f'에이전트 판정 {result["category"]}' + (" (검증 실패→B)" if problems else "") + ": "
                    + " / ".join(x.get("claim", "") for x in result.get("reasons", []))[:300])
    if usage["calls"]:
        print(f"  에이전트 호출 {usage['calls']}회, ${judge.cost(model, usage):.4f}")


def verdict(row):
    if not row["vulnerable"]:
        return "영향 없음 (수정 버전 이상)"
    return {"A": "영향 · 실행됨 (코드가 직접 사용)", "B": "영향 · 실행됨 (프레임워크 경유)",
            "C": "포함됐지만 실행 안 됨", "?": "포함 · 실행 여부 판정 필요"}[row["category"]]


def render(title, services, rows):
    names = [s["name"] for s in services]
    hit = {r["service"] for r in rows if r["vulnerable"]}
    running = {r["service"] for r in rows if r["vulnerable"] and r["category"] in ("A", "B")}
    body = "".join(
        f'<tr><td><b>{esc(r["service"])}</b></td><td style="font-family:var(--mono)">{esc(r["package"])}</td>'
        f'<td>{esc(r["version"])}</td><td>{esc(r["path"])}</td><td>{esc(verdict(r))}<div class="meta">{esc(r["why"])}</div>'
        + (f'<div class="meta">조치: {esc(r["fix"])}</div>' if r.get("fix") else "") + "</td></tr>"
        for r in sorted(rows, key=lambda r: (not r["vulnerable"], r["category"])))
    absent = [n for n in names if n not in {r["service"] for r in rows}]
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>역조회 · {esc(title)}</title><style>{CSS}</style></head>
<body><main><h1>역조회 · {esc(title)}</h1>
<div class="meta">등록된 서비스 {len(names)}개 ({esc(", ".join(names))}) · SBOM·사용 인덱스 기준</div>
<div class="funnel">
<div class="tile"><div class="l">등록 서비스</div><div class="n">{len(names)}</div></div>
<div class="tile"><div class="l">취약 버전 포함</div><div class="n">{len(hit)}</div></div>
<div class="tile p1"><div class="l">그중 실행 중</div><div class="n">{len(running)}</div></div>
<div class="tile c"><div class="l">미포함</div><div class="n">{len(absent)}</div><div class="s">{esc(", ".join(absent) or "-")}</div></div>
</div>
<div class="card"><div class="body" style="border-top:0"><table>
<tr><th>서비스</th><th>패키지</th><th>버전</th><th>도입 경로</th><th>판단</th></tr>{body}</table></div></div>
<footer>실행 여부: 기존 에이전트 판정이 있으면 그 결과, 없으면 사용 인덱스(소스 import·직접 선언)로 1차 판단하고 나머지는 "판정 필요"로 표시합니다.</footer>
</main></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--package")
    ap.add_argument("--fixed", help="수정 버전 (이 버전 미만이 취약)")
    ap.add_argument("--html")
    ap.add_argument("--judge", action="store_true", help="실행 여부가 미정인 서비스만 에이전트로 판단")
    ap.add_argument("--title", help="취약점 설명 (에이전트 판단에 참고)")
    ap.add_argument("--model", default="gpt-5.5")
    args = ap.parse_args()
    services = load_services()
    if args.cve:
        title, rows = args.cve, lookup_cve(services, args.cve)
    elif args.package:
        title = f'{args.package}{" < " + args.fixed if args.fixed else ""}'
        rows = lookup_package(services, args.package, args.fixed)
    else:
        ap.error("--cve 또는 --package가 필요합니다")
    groups = {r["package"].split(":")[0] for r in rows}
    if len(groups) > 1:
        print(f"  ⚠ 서로 다른 group {len(groups)}개가 같은 이름으로 일치: {', '.join(sorted(groups))} "
              f"— 별개 라이브러리일 수 있으니 group:artifact로 다시 조회하세요")
    if args.judge:
        judge_unknown(services, rows, args.cve or f"NEW:{title}", args.fixed, args.title, args.model)
    print(f"[{title}] 등록 서비스 {len(services)}개")
    for r in sorted(rows, key=lambda r: (not r["vulnerable"], r["category"])):
        print(f'  {r["service"]:14} {r["package"]} {r["version"]:14} {verdict(r)} — {r["why"]}')
    if not rows:
        print("  해당 패키지/취약점을 가진 서비스 없음")
    if args.html:
        pathlib.Path(args.html).write_text(render(title, services, rows))
        print("saved", args.html)


if __name__ == "__main__":
    main()
