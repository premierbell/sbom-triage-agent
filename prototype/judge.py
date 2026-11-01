"""취약 패키지마다 LLM 에이전트가 도구로 근거를 모아 분류·우선순위·조치안을 내고, 그 근거 인용을 검증한다.

usage: OPENAI_API_KEY=... judge.py <enriched.json> <reach.json> <deptree.txt> <repo_dir> [model]
"""
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request

MAX_TURNS = 8
MAX_LINE = 300
CONFIG_FILES = ("*.yml", "*.yaml", "*.properties", "*.xml")

SYSTEM = """너는 SW 공급망 취약점 분류 에이전트다. 취약 패키지 하나에 대해 도구로 근거를 모은 뒤 판단한다.

분류(category)
- A: 이 서비스의 소스 코드가 해당 라이브러리를 직접 사용한다
- B: 소스가 직접 import하지 않아도(또는 인터페이스만 import해도) 프레임워크·다른 라이브러리가 런타임에 실행한다
- C: 설정이나 구조상 취약 기능이 실행되지 않는다 (예: 기능이 설정으로 꺼짐, 해당 코덱/모듈 미사용). 반드시 설정·소스 검색 결과로 뒷받침해야 한다

우선순위(priority): P1=지금 조치, P2=다음 정기 업데이트, P3=모니터링
조치 유형(action)
- 1: Spring Boot 패치 버전업 (현재 Boot {boot})
- 2: Spring Boot가 관리하는 라이브러리 버전 오버라이드
- 3: 빌드 파일에 버전을 직접 적은 의존성의 업그레이드
- 4: 그 밖의 전이 의존성 개별 대응

규칙
- 사실(CVE, 버전, 파일, 설정)은 반드시 근거 ID(E*, T*)로 인용한다. 근거에 없는 CVE ID나 버전을 만들어내지 않는다
- C로 판단하려면 설정 또는 소스 검색(T*) 근거가 최소 1개 있어야 한다
- 확신이 없으면 우선순위를 낮추지 말고 B로 둔다
- claim과 fix는 한국어로 쓴다
- 최종 답은 JSON만 출력한다:
{"category":"A|B|C","priority":"P1|P2|P3","action":1-4,
 "reasons":[{"claim":"...","evidence":["E1","T2"]}],
 "fix":"구체적 조치 한두 문장 (수정 버전은 근거의 fixed 버전 중에서)"}"""

# v2: v1 오판 3건(lz4/snappy/commons-lang3) 분석 후 추가한 규칙. 같은 15건으로만 재면 과적합이라 WE 7건(held-out)으로 따로 잰다
SYSTEM_V2_EXTRA = """
추가 규칙 (v2)
- C에는 "기본값이 꺼져 있고, 켜는 설정이 없음"도 포함된다. 이때는 (1) 그 기능의 기본값이 꺼짐이라는 점을 claim에 명시하고 (2) 켜는 설정을 검색했는데 없다는 검색 결과(T*)를 인용한다. 기본값을 확신하지 못하면 C로 두지 않는다
- 패키지 이름으로만 검색하지 말고, 이 패키지를 끌고 온 직접 의존성(dependency_roots)과 중간 라이브러리의 설정도 검색한다 (예: 그 라이브러리 이름 접두어의 enabled/disabled 설정, 운영(prod) 프로파일 설정)
- 프로파일별 설정이 다르면 운영(prod) 기준으로 판단하고 claim에 프로파일을 적는다
- "사용 흔적·설정이 검색되지 않음"만으로는 C가 아니다. 자동 구성(auto-configuration, docker-compose 연동 등)으로 설정 없이 동작할 수 있다. C는 꺼져 있다는 적극적 근거(비활성화 설정 또는 기본값이 꺼짐)가 있을 때만
- 초기 근거(E*)와 모순되는 주장을 하지 않는다"""

TOOLS = [
    {"type": "function", "function": {
        "name": "search_config",
        "description": "src/main/resources의 설정 파일(yml/yaml/properties/xml)에서 정규식(대소문자 무시)으로 검색. 결과가 없으면 빈 결과도 근거가 된다.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "search_source",
        "description": "src/main 아래 Java·Kotlin 소스에서 정규식(대소문자 무시)으로 검색. 최대 20줄.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "dependency_path",
        "description": "Gradle runtimeClasspath 의존성 트리에서 artifact(group:name 일부)가 나오는 줄과 그 상위 경로.",
        "parameters": {"type": "object", "properties": {"artifact": {"type": "string"}}, "required": ["artifact"]}}},
    {"type": "function", "function": {
        "name": "build_file",
        "description": "빌드 파일(build.gradle(.kts) 또는 pom.xml)에서 정규식으로 검색 (직접 선언·버전 고정 여부 확인용).",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}},
]


def grep(pattern, path, limit=20, include=()):
    flags = [f"--include={i}" for i in include]
    out = subprocess.run(["grep", "-rniE", *flags, "--", pattern, path], capture_output=True, text=True).stdout
    # 압축된 프론트 번들처럼 한 줄이 매우 긴 파일이 걸리면 토큰이 폭증하므로 줄마다 자른다
    prefix = path + ":" if os.path.isfile(path) else path + "/"  # 파일 하나를 검색하면 grep이 경로 없이 줄 번호부터 낸다
    lines = [line.replace(prefix, "")[:MAX_LINE] for line in out.splitlines()]
    return lines[:limit] + ([f"... 외 {len(lines) - limit}줄"] if len(lines) > limit else [])


def dependency_path(deptree_lines, artifact):
    hits = []
    for i, line in enumerate(deptree_lines):
        if artifact in line:
            depth = line.find("--- ")
            chain = [line.strip()]
            for prev in reversed(deptree_lines[:i]):
                d = prev.find("--- ")
                if 0 <= d < depth:
                    chain.append(prev.strip())
                    depth = d
            hits.append(" <- ".join(chain))
    return hits[:10]


# python.org 설치판은 기본 CA 번들이 없어 macOS 시스템 인증서를 직접 지정한다.
# 키를 curl 인자로 넘기면 실패 시 traceback에 키가 그대로 찍혀서 urllib로 바꿨다.
SSL_CONTEXT = ssl.create_default_context(cafile="/etc/ssl/cert.pem")


# USD / 1M tokens (input, cached input, output). 2026-10-29 OpenAI 대시보드 청구액과 역산 일치 확인
PRICES = {"gpt-5.5": (5.00, 0.50, 30.00), "gpt-5.4-mini": (0.75, 0.075, 4.50)}


def cost(model, usage):
    inp, cached, out = PRICES[model]
    return ((usage["input"] - usage["cached"]) * inp + usage["cached"] * cached + usage["output"] * out) / 1e6


USAGE_LOCK = threading.Lock()


def call_openai(model, messages, usage, retries=5):
    body = json.dumps({"model": model, "messages": messages, "tools": TOOLS}).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=180) as resp:
                data = json.load(resp)
            u = data["usage"]
            with USAGE_LOCK:  # 병렬 판단이 같은 usage를 갱신한다
                usage["calls"] += 1
                usage["input"] += u["prompt_tokens"]
                usage["cached"] += (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
                usage["output"] += u["completion_tokens"]
            return data["choices"][0]["message"]
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == retries - 1:
                raise RuntimeError(f"OpenAI 호출 실패 ({type(e).__name__}: {getattr(e, 'code', '')})") from None
            # 429(요청 한도)면 서버가 알려준 대기 시간을 따르고, 그 밖의 일시 오류는 점점 길게 기다린다
            wait = 5 * (attempt + 1)
            if getattr(e, "code", None) == 429:
                with USAGE_LOCK:
                    usage["rate_limited"] = usage.get("rate_limited", 0) + 1
                try:
                    wait = max(wait, float(e.headers.get("retry-after", wait)))
                except (TypeError, ValueError):
                    pass
            time.sleep(wait)


def initial_evidence(pkg, vulns, reach_row):
    ev = {}
    for i, v in enumerate(vulns, 1):
        ev[f"E{i}"] = {
            "cve": v["VulnerabilityID"], "severity": v["Severity"], "epss": v["epss"], "kev": v["kev"],
            "installed": v["InstalledVersion"], "fixed": v.get("FixedVersion"), "title": v.get("Title", "")[:160],
        }
    n = len(ev)
    ev[f"E{n + 1}"] = {"dependency_roots": reach_row["via"], "declared_directly": reach_row["direct"],
                       "embedded_in_jar": reach_row.get("embedded_in")}
    ev[f"E{n + 2}"] = {"source_files_importing": reach_row["import_files"], "imported_packages": reach_row["used_packages"]}
    return ev


def validate(result, evidence, tool_kinds, reach_row):
    """근거 인용 검증. 위반 목록을 돌려준다."""
    problems = []
    known_cves = {e["cve"] for e in evidence.values() if "cve" in e}
    if result.get("category") not in ("A", "B", "C"):
        problems.append("category 형식 오류")
    if not result.get("reasons"):
        problems.append("근거 없음")
    for r in result.get("reasons", []):
        missing = [e for e in r.get("evidence", []) if e not in evidence]
        if missing:
            problems.append(f"존재하지 않는 근거 인용 {missing}")
        if not r.get("evidence"):
            problems.append(f"인용 없는 주장: {r.get('claim', '')[:40]}")
    text = json.dumps(result, ensure_ascii=False)
    for cve in set(re.findall(r"(?:CVE-\d{4}-\d+|GHSA-[\w-]+)", text)) - known_cves:
        problems.append(f"근거에 없는 취약점 ID {cve}")
    if result.get("category") == "C":
        cited = {e for r in result.get("reasons", []) for e in r.get("evidence", [])}
        if not any(tool_kinds.get(e) in ("search_config", "search_source") for e in cited):
            problems.append("C 판정인데 설정/소스 검색 근거 미인용")
        if reach_row["direct"]:
            problems.append("직접 선언한 의존성을 C로 판정")
    return problems


def system_prompt():
    prompt = SYSTEM.replace("{boot}", os.environ.get("BOOT", "버전 미상"))
    return prompt + SYSTEM_V2_EXTRA if os.environ.get("PROMPT") == "v2" else prompt


def judge(model, pkg, vulns, reach_row, repo, deptree_lines, usage, tool_budget=None, grep_limit=20):
    evidence = initial_evidence(pkg, vulns, reach_row)
    tool_kinds = {}
    messages = [
        {"role": "system", "content": system_prompt()},
        {"role": "user", "content": f"패키지: {pkg}\n초기 근거:\n{json.dumps(evidence, ensure_ascii=False, indent=1)}"},
    ]
    trace = []
    for _ in range(MAX_TURNS):
        msg = call_openai(model, messages, usage)
        messages.append(msg)
        if not msg.get("tool_calls"):
            content = msg["content"].strip()
            content = content[content.find("{"):content.rfind("}") + 1]
            result = json.loads(content)
            problems = validate(result, evidence, tool_kinds, reach_row)
            # 리포트에서 근거 원문을 보여줄 수 있게, 인용된 근거만 결과에 붙인다
            cited = {e for r in result.get("reasons", []) for e in r.get("evidence", [])}
            result["evidence"] = {k: evidence[k] for k in sorted(cited) if k in evidence}
            if problems:
                # 검증 실패 시 안전한 쪽(B, 우선순위 유지)으로 되돌리고 사람 검토로 넘긴다
                result = {**result, "llm_category": result.get("category"), "category": "B", "needs_review": True}
            return result, problems, trace
        for tc in msg["tool_calls"]:
            name, args = tc["function"]["name"], json.loads(tc["function"]["arguments"])
            if tool_budget is not None and len(tool_kinds) >= tool_budget:
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": "도구 호출 예산 초과. 지금까지 모은 근거로 최종 JSON을 출력하라."})
                continue
            if name == "search_config":
                out = grep(args["pattern"], f"{repo}/src/main/resources", grep_limit, include=CONFIG_FILES)
            elif name == "search_source":
                out = grep(args["pattern"], f"{repo}/src/main", grep_limit, include=("*.java", "*.kt"))
            elif name == "build_file":
                build = next(f for f in ("build.gradle.kts", "build.gradle", "pom.xml") if os.path.exists(f"{repo}/{f}"))
                out = grep(args["pattern"], f"{repo}/{build}", grep_limit)
            else:
                out = dependency_path(deptree_lines, args["artifact"])
            tid = f"T{len(tool_kinds) + 1}"
            tool_kinds[tid] = name
            evidence[tid] = {"tool": name, "args": args, "result": out}
            trace.append(f"{tid} {name}({args}) -> {len(out)}줄")
            messages.append({"role": "tool", "tool_call_id": tc["id"],
                             "content": json.dumps({"id": tid, "result": out or ["(결과 없음)"]}, ensure_ascii=False)})
    raise RuntimeError(f"{pkg}: {MAX_TURNS}턴 안에 결론 못 냄")


def rule_priority(vulns):
    return "P1" if any(v["Severity"] in ("CRITICAL", "HIGH") or v["kev"] for v in vulns) else "P2"


def rule_decision(row, vulns):
    """LLM 없이 정해지는 경우. A: 소스가 직접 import / B: 직접 선언했지만 import 없음(C 불가)."""
    # jakarta.*/javax.*는 스펙 인터페이스(예: tomcat jar 안의 서블릿 API)라 구현체를 직접 쓴다는 근거가 못 된다
    used = [p for p in row["used_packages"] if not p.startswith(("jakarta.", "javax."))]
    if used:
        return {"category": "A", "priority": rule_priority(vulns), "action": None, "decided_by": "rule",
                "reasons": [{"claim": f"소스가 {', '.join(used)} import",
                             "evidence": ["reach"]}]}
    if row["direct"]:
        return {"category": "B", "priority": rule_priority(vulns), "action": None, "decided_by": "rule",
                "reasons": [{"claim": "build 파일에 직접 선언 — 미사용 판단 불가, 실행됨으로 취급", "evidence": ["reach"]}]}
    return None


def group_key(row):
    """같은 groupId + 같은 도입 경로(직접 의존성 집합)면 같은 판단을 공유한다."""
    return row["package"].split(":")[0], tuple(row["via"])


def main_v3(vulns, reach_rows, deptree_lines, repo, model, usage):
    """비용 절감 파이프라인: 규칙으로 정해지는 건 LLM 생략 → 나머지는 도입 경로 단위로 묶어 1회 판단 → 결과 전파."""
    import kb  # judge를 import하므로 순환을 피하려고 여기서 불러온다
    results, groups = {}, {}
    for pkg, row in reach_rows.items():
        pv = [v for v in vulns if v["PkgName"] == pkg]
        decided = rule_decision(row, pv) or kb.decide(row, deptree_lines, repo)
        if decided:
            results[pkg] = {"result": decided, "problems": [], "trace": []}
        else:
            groups.setdefault(group_key(row), []).append(pkg)
    def judge_group(item):
        (group_id, via), members = item
        pv = [v for v in vulns if v["PkgName"] in members]
        names = members[0] if len(members) == 1 else f"{group_id}:{{{', '.join(m.split(':')[1] for m in members)}}}"
        first = reach_rows[members[0]]
        row = {"via": list(via), "direct": False, "import_files": [], "used_packages": [],
               "embedded_in": first.get("embedded_in") if len(members) == 1 else None}
        result, problems, trace = judge(model, names, pv, row, repo, deptree_lines, usage,
                                        tool_budget=12 if len(members) > 1 else 8, grep_limit=12)
        result["decided_by"] = f"llm(group of {len(members)})" if len(members) > 1 else "llm"
        return members, result, problems, trace

    # 묶음끼리는 서로 독립이라 병렬로 판단한다. 한 묶음 안의 도구 호출 순서는 그대로 순차
    workers = int(os.environ.get("JUDGE_WORKERS", "4"))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for members, result, problems, trace in pool.map(judge_group, groups.items()):
            for m in members:
                results[m] = {"result": result, "problems": problems, "trace": trace}
    return results


def main(enriched, reach, deptree, repo, model="gpt-5.4-mini"):
    vulns = json.load(open(enriched))
    reach_rows = {r["package"]: r for r in json.load(open(reach))}
    deptree_lines = open(deptree).read().splitlines()
    usage = {"calls": 0, "input": 0, "cached": 0, "output": 0}
    pipeline = os.environ.get("PIPELINE", "v2")
    if pipeline == "v3":
        results = main_v3(vulns, reach_rows, deptree_lines, repo, model, usage)
    else:
        results = {}
        for pkg, row in reach_rows.items():
            pv = [v for v in vulns if v["PkgName"] == pkg]
            result, problems, trace = judge(model, pkg, pv, row, repo, deptree_lines, usage)
            results[pkg] = {"result": result, "problems": problems, "trace": trace}
    for pkg, r in results.items():
        res = r["result"]
        print(f"{pkg.split(':')[1]:22} {res['category']} {res['priority']} {res.get('decided_by', 'llm'):18}"
              f" | 도구 {len(r['trace'])}회 | 검증 {'OK' if not r['problems'] else r['problems']}", flush=True)
    usage["usd"] = round(cost(model, usage), 4)
    print(f"usage: {usage}")
    out = enriched.replace(".enriched.json", f".judge.{model}.{os.environ.get('PROMPT', 'v1')}"
                                             f"{'.v3pipe' if pipeline == 'v3' else ''}{os.environ.get('RUN', '')}.json")
    json.dump({**results, "_usage": usage}, open(out, "w"), ensure_ascii=False, indent=1)
    print("saved", out)


if __name__ == "__main__":
    main(*sys.argv[1:])
