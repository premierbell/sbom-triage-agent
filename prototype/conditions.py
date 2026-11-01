"""CVE 공격 조건 분석 — 실행되는 패키지의 고위험 CVE(KEV 또는 EPSS 높음)만, 설명에 적힌 공격 조건이
이 서비스에서 충족되는지 에이전트가 도구로 확인한다.

LLM의 결론은 그대로 쓰지 않는다. 조건마다 (1) CVE 설명 원문 인용이 실제로 있는지, (2) "미충족"이면 검색 근거를
인용했는지 코드로 검사하고, 통과한 조건만으로 최종 판정을 다시 계산한다.

usage: conditions.py <runs/이름 디렉토리> [model]   — 기존 분석 결과에 조건 분석을 붙이고 리포트를 다시 만든다
"""
import json
import os
import pathlib
import re
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import judge  # noqa: E402

EPSS_THRESHOLD = 0.1
# 미충족 근거로 인정하는 도구. dependency_path는 "영향 버전 이하" 같은 버전 조건의 근거가 된다
SEARCH_TOOLS = ("search_config", "search_source", "build_file", "dependency_path")
EVIDENCE_ID = re.compile(r"\b([TE]\d+)\b")

SYSTEM = """너는 CVE 공격 조건 분석 에이전트다. CVE 설명(description)에서 공격이 성립하는 데 필요한 조건을 뽑고,
이 서비스에서 각 조건이 충족되는지 도구로 확인한다.

규칙
- 조건은 반드시 설명 원문에서 그대로 인용(quote)한다. 설명에 없는 조건을 지어내지 않는다.
  설명이 공격 조건을 명시하지 않으면 scenarios를 빈 배열로 두고 verdict는 unknown.
- 설명에 공격 시나리오가 여러 개면(예: 정보 노출용 조건 목록, 원격 코드 실행용 조건 목록) 시나리오별로 나눈다.
  한 시나리오 안의 조건은 모두 충족돼야 공격이 성립한다고 본다.
- conditions에는 "공격이 성립하려면 참이어야 하는 것"만 넣는다. "이게 참이면 공격이 막힌다"는 완화 요인
  (예: "requests are blocked when ... is in use", "not vulnerable if ...")은 conditions가 아니라 mitigations에 넣는다.
  영향 버전 범위는 조건이 아니고, 업그레이드 권고도 완화 요인이 아니다(둘 다 이미 스캐너가 다룸).
- status: met(충족 근거 있음) / not_met(미충족 근거 있음) / unknown(확인 불가)
- not_met은 설정·소스·빌드 파일 검색 결과(T*)를 반드시 인용한다. 원문에 "(disabled by default)"처럼 기본값이 꺼져
  있다고 적혀 있고 그 기능을 켜는 설정·코드가 검색되지 않으면 not_met이다.
  원문이 기본값을 말하지 않으면 기억으로 단정하지 말고 unknown으로 둔다.
- 프레임워크(Spring Boot 등)가 설정 키로 기능을 켤 수 있으므로 관련 설정 키 이름과 소스 코드를 모두 검색한다.
- 확신이 없으면 unknown. meaning과 summary는 한국어로 쓴다. evidence에는 "T1"처럼 근거 ID만 쓴다.
- 최종 답은 JSON만:
{"scenarios":[{"name":"...","conditions":[{"quote":"설명 원문 그대로","meaning":"...","status":"met|not_met|unknown","evidence":["T1"]}]}],
 "mitigations":[{"quote":"설명 원문 그대로","meaning":"...","status":"met|not_met|unknown","evidence":["T2"]}],
 "verdict":"exploitable|not_exploitable|unknown","summary":"..."}"""


def norm(text):
    return re.sub(r"\s+", " ", text or "").strip().lower()


def targets(vulns, results):
    """실행되는 패키지(A·B)의 KEV 또는 EPSS 높은 취약점."""
    running = {p for p, r in results.items() if r["result"].get("category") in ("A", "B")}
    return [v for v in vulns if v["PkgName"] in running and (v["kev"] or (v["epss"] or 0) >= EPSS_THRESHOLD)]


def validate(result, description, tool_kinds):
    """조건마다 인용·근거를 검사해 무효인 건 unknown으로 바꾸고, 판정을 다시 계산한다."""
    desc = norm(description)
    problems = []
    for sc in result.get("scenarios", []):
        for c in sc.get("conditions", []):
            # 에이전트가 "T1: 검색 결과 없음"처럼 설명을 붙여 적기도 해서 앞의 ID만 뽑는다
            c["evidence"] = [m.group(1) for e in c.get("evidence", []) if (m := EVIDENCE_ID.search(str(e)))]
            if norm(c.get("quote")) not in desc or not norm(c.get("quote")):
                problems.append(f"원문에 없는 인용: {c.get('quote', '')[:50]}")
                c["llm_status"], c["status"] = c.get("status"), "unknown"
            elif c.get("status") == "not_met" and not any(tool_kinds.get(e) in SEARCH_TOOLS for e in c.get("evidence", [])):
                problems.append(f"검색 근거 없는 미충족: {c.get('quote', '')[:50]}")
                c["llm_status"], c["status"] = c.get("status"), "unknown"
    scenarios = result.get("scenarios", [])
    if scenarios and all(any(c["status"] == "not_met" for c in sc.get("conditions", [])) for sc in scenarios):
        verdict = "not_exploitable"
    elif any(sc.get("conditions") and all(c["status"] == "met" for c in sc["conditions"]) for sc in scenarios):
        verdict = "exploitable"
    else:
        verdict = "unknown"
    result["llm_verdict"], result["verdict"] = result.get("verdict"), verdict
    return problems


def analyze_one(v, row, repo, deptree_lines, model, usage):
    evidence = {"E1": {"cve": v["VulnerabilityID"], "package": v["PkgName"], "installed": v["InstalledVersion"],
                       "severity": v["Severity"], "kev": v["kev"], "epss": v["epss"]},
                "E2": {"dependency_roots": row["via"], "declared_directly": row["direct"],
                       "source_files_importing": row["import_files"][:10]}}
    description = v.get("Description") or v.get("Title") or ""
    user = (f"CVE: {v['VulnerabilityID']} ({v['PkgName']} {v['InstalledVersion']})\n"
            f"설명(description) 원문:\n{description[:3000]}\n\n초기 근거:\n{json.dumps(evidence, ensure_ascii=False)}")
    result, tool_kinds, trace = judge.run_agent(model, SYSTEM, user, evidence, repo, deptree_lines, usage,
                                                tool_budget=8, grep_limit=12, label=v["VulnerabilityID"])
    problems = validate(result, description, tool_kinds)
    cited = {e for sc in result.get("scenarios", []) for c in sc.get("conditions", []) for e in c.get("evidence", [])}
    result["evidence"] = {k: evidence[k] for k in sorted(cited) if k in evidence}
    return {"result": result, "problems": problems, "trace": trace}


def analyze(vulns, results, rows, repo, deptree_lines, model, usage, workers=4):
    by_pkg = {r["package"]: r for r in rows}
    todo = targets(vulns, results)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        done = pool.map(lambda v: analyze_one(v, by_pkg[v["PkgName"]], repo, deptree_lines, model, usage), todo)
        return {f'{v["VulnerabilityID"]}|{v["PkgName"]}': r for v, r in zip(todo, done)}


def revalidate(s):
    """LLM 재호출 없이, 저장된 조건 분석 결과에 현재 검증 규칙을 다시 적용한다 (도구 종류는 trace에서 복원)."""
    by_id = {f'{v["VulnerabilityID"]}|{v["PkgName"]}': v for v in s["vulns"]}
    for key, c in s.get("conditions", {}).items():
        r = c["result"]
        for sc in r.get("scenarios", []):
            for cd in sc.get("conditions", []):
                if "llm_status" in cd:
                    cd["status"] = cd.pop("llm_status")
        if "llm_verdict" in r:
            r["verdict"] = r.pop("llm_verdict")
        kinds = {t.split()[0]: t.split()[1].split("(")[0] for t in c["trace"]}
        v = by_id[key]
        c["problems"] = validate(r, v.get("Description") or v.get("Title") or "", kinds)


def main(run_dir, model="gpt-5.5"):
    import report
    run = pathlib.Path(run_dir)
    s = json.loads((run / "summary.json").read_text())
    usage = {"calls": 0, "input": 0, "cached": 0, "output": 0}
    deptree_lines = (run / "deptree.txt").read_text().splitlines()
    s["conditions"] = analyze(s["vulns"], s["results"], s["packages"], s["module"], deptree_lines, model, usage)
    usage["usd"] = round(judge.cost(model, usage), 4)
    s["conditions_usage"] = usage
    (run / "summary.json").write_text(json.dumps(s, ensure_ascii=False, indent=1))
    (run / "report.html").write_text(report.render(s))
    for key, c in s["conditions"].items():
        r = c["result"]
        print(f'{key:52} {r["verdict"]:16} (LLM {r.get("llm_verdict")}) 검증문제 {len(c["problems"])} — {r.get("summary", "")[:90]}')
    print(f"조건 분석 {len(s['conditions'])}건, LLM {usage['calls']}회 ${usage['usd']}")


if __name__ == "__main__":
    if sys.argv[1] == "--revalidate":
        import report
        run = pathlib.Path(sys.argv[2])
        data = json.loads((run / "summary.json").read_text())
        revalidate(data)
        (run / "summary.json").write_text(json.dumps(data, ensure_ascii=False, indent=1))
        (run / "report.html").write_text(report.render(data))
        for key, c in data["conditions"].items():
            print(f'{key:52} {c["result"]["verdict"]:16} (LLM {c["result"].get("llm_verdict")}) 검증문제 {c["problems"]}')
    else:
        main(*sys.argv[1:])
