"""run.py가 만든 summary를 사람이 읽는 HTML 리포트로 만든다 (외부 리소스 없는 단일 파일)."""
import html
import json

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
CATEGORY = {
    "A": ("코드가 직접 사용", "cat-a"),
    "B": ("프레임워크가 실행", "cat-b"),
    "C": ("실행 안 됨", "cat-c"),
    "?": ("미판정", "cat-u"),
}
PRIORITY = {"P1": "지금 조치", "P2": "다음 정기 업데이트", "P3": "모니터링"}

CSS = """
:root{--bg:#f7f7f5;--surface:#fff;--text:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;
--p1:#c2410c;--p1-bg:#fff1e8;--ok:#15803d;--ok-bg:#ecfdf3;--info:#1d4ed8;--info-bg:#eef3ff;
--warn:#a16207;--warn-bg:#fef9e7;--chip:#f0f0ee;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--surface:#1c1c1f;--text:#ececef;--muted:#9a9aa2;
--line:#2e2e33;--p1:#fb923c;--p1-bg:#2a1a10;--ok:#4ade80;--ok-bg:#10241a;--info:#93b4ff;--info-bg:#151d33;
--warn:#facc15;--warn-bg:#2a2410;--chip:#26262b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Pretendard","Noto Sans KR",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:17px;margin:36px 0 12px}
.meta{color:var(--muted);font-size:13px}
.funnel{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:24px 0 8px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .n{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}
.tile .l{font-size:13px;color:var(--muted)}
.tile .s{font-size:12px;color:var(--muted)}
.tile.p1 .n{color:var(--p1)} .tile.c .n{color:var(--ok)}
.callout{background:var(--info-bg);color:var(--text);border:1px solid var(--line);border-left:3px solid var(--info);
border-radius:8px;padding:12px 14px;margin:16px 0;font-size:14px}
.callout.warn{background:var(--warn-bg);border-left-color:var(--warn)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin:8px 0;overflow:hidden}
.card summary{list-style:none;cursor:pointer;padding:12px 16px;display:grid;
grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center}
.card summary::-webkit-details-marker{display:none}
.pkg{font-family:var(--mono);font-size:14px;font-weight:600;overflow-wrap:anywhere}
.pkg .ver{color:var(--muted);font-weight:400}
.badges{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.badge{font-size:12px;padding:2px 8px;border-radius:999px;background:var(--chip);white-space:nowrap}
.sev-CRITICAL,.sev-HIGH{color:var(--p1);background:var(--p1-bg)}
.cat-c{color:var(--ok);background:var(--ok-bg)} .cat-b,.cat-a{color:var(--info);background:var(--info-bg)}
.review{color:var(--warn);background:var(--warn-bg)}
.sub{grid-column:1/-1;font-size:13px;color:var(--muted)}
.body{border-top:1px solid var(--line);padding:12px 16px 16px;font-size:14px}
.reason{margin:6px 0}
.ev{font-family:var(--mono);font-size:11px;padding:1px 6px;border-radius:4px;background:var(--chip);margin-left:4px}
.fix{margin-top:10px;padding:8px 10px;border-radius:6px;background:var(--chip)}
pre{font-family:var(--mono);font-size:12px;background:var(--chip);padding:10px;border-radius:6px;
overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:260px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}
td.num{font-variant-numeric:tabular-nums}
td:first-child{white-space:nowrap;font-family:var(--mono);font-size:12px}
.empty{color:var(--muted);font-size:14px}
footer{margin-top:40px;font-size:12px;color:var(--muted)}
@media (max-width:640px){.funnel{grid-template-columns:repeat(2,1fr)}.card summary{grid-template-columns:1fr}
.badges{justify-content:flex-start}}
"""


def esc(x):
    return html.escape(str(x))


def epss_text(epss):
    return "-" if epss is None else f"{epss:.3f}"


def package_view(pkg, row, vulns, judged, act):
    res = judged["result"]
    vs = sorted(vulns, key=lambda v: (SEV_ORDER.get(v["Severity"], 9), -(v["epss"] or 0)))
    solved = set(act.get("solved_ids", [])) if act else set()
    left = [v for v in vs if v["VulnerabilityID"] not in solved]
    category = res.get("category", "?")
    urgent = any(v["Severity"] in ("CRITICAL", "HIGH") or v["kev"] for v in left)
    # 우선순위는 LLM이 아니라 규칙으로: 실행되고(A·B) Boot 패치 후에도 남는 CRITICAL/HIGH/KEV가 있으면 P1
    priority = "-" if category == "?" else ("P3" if category == "C" else ("P1" if urgent else "P2"))
    return {
        "pkg": pkg, "row": row, "vulns": vs, "left": left, "solved": solved, "res": res, "act": act or {},
        "problems": judged["problems"], "category": category, "priority": priority,
        "max_sev": (left or vs)[0]["Severity"] if vs else "UNKNOWN",
        "max_epss": max((v["epss"] or 0) for v in (left or vs)) if vs else 0,
        "kev": any(v["kev"] for v in left),
    }


def card(p, open_card=False):
    label, cls = CATEGORY.get(p["category"], CATEGORY["?"])
    by = p["res"].get("decided_by", "llm")
    KB_NAMES = {"kb-aws-sync": "AWS 동기 클라이언트", "kb-kafka-codec": "Kafka 압축 미사용",
                "kb-springdoc": "Swagger 설정", "kb-framework-core": "프레임워크 핵심"}
    if by == "rule":
        by_label = "규칙"
    elif by.startswith("rule:"):
        by_label = "규칙 · " + KB_NAMES.get(by.split(":", 1)[1], by.split(":", 1)[1])
    elif by == "llm":
        by_label = "에이전트"
    else:
        by_label = by.replace("llm(group of ", "에이전트 · 묶음 ").rstrip(")")
    count = f'남는 {len(p["left"])} / {len(p["vulns"])}건' if p["solved"] else f'{len(p["vulns"])}건'
    badges = [f'<span class="badge sev-{esc(p["max_sev"])}">{esc(p["max_sev"])} · {count}</span>',
              f'<span class="badge {cls}">{p["category"]} {esc(label)}</span>']
    if p["kev"]:
        badges.insert(0, '<span class="badge sev-CRITICAL">KEV</span>')
    if p["res"].get("needs_review"):
        badges.append('<span class="badge review">사람 검토</span>')
    via = ", ".join("경로 불명(Maven 버전 조정)" if v.startswith("maven-mediated:") else v.split(":")[1]
                    for v in p["row"]["via"]) or "-"
    origin = ("직접 선언" if p["row"]["direct"] else
              f'{esc(p["row"]["embedded_in"])} 안에 포함(shaded)' if p["row"].get("embedded_in") else "전이 의존성 · " + esc(via))
    sub = (f'{origin} · 최대 EPSS {p["max_epss"]:.3f}'
           f' · 판정 {esc(by_label)}')

    reasons = "".join(
        f'<div class="reason">· {esc(r.get("claim", ""))}'
        + "".join(f'<span class="ev">{esc(e)}</span>' for e in r.get("evidence", [])) + "</div>"
        for r in p["res"].get("reasons", []))
    fix = f'<div class="fix"><b>조치</b> {esc(p["act"]["fix"])}</div>' if p["act"].get("fix") else ""
    problems = (f'<div class="callout warn">검증에서 걸린 항목: {esc("; ".join(p["problems"]))} — '
                f'LLM 원래 판정 {esc(p["res"].get("llm_category"))} → 안전하게 B로 되돌림</div>') if p["problems"] else ""
    evidence = p["res"].get("evidence") or {}
    ev_html = (f'<details><summary class="meta" style="cursor:pointer">인용된 근거 원문 {len(evidence)}개</summary>'
               f'<pre>{esc(json.dumps(evidence, ensure_ascii=False, indent=1))}</pre></details>') if evidence else ""
    rows = "".join(
        f'<tr><td>{esc(v["VulnerabilityID"])}</td><td>{esc(v["Severity"])}</td>'
        f'<td class="num">{epss_text(v["epss"])}</td>'
        f'<td>{esc(v.get("FixedVersion") or "-")}</td>'
        f'<td>{"Boot 패치로 해결" if v["VulnerabilityID"] in p["solved"] else "남음"}</td>'
        f'<td>{esc(v.get("Title", "")[:80])}</td></tr>'
        for v in p["vulns"])
    table = (f'<details><summary class="meta" style="cursor:pointer">취약점 {len(p["vulns"])}건 보기</summary>'
             f'<table><tr><th>ID</th><th>등급</th><th>EPSS</th><th>수정 버전</th><th>Boot 패치 후</th><th>내용</th></tr>'
             f'{rows}</table></details>')
    return (f'<details class="card"{" open" if open_card else ""}><summary><div class="pkg">{esc(p["pkg"])} '
            f'<span class="ver">{esc(p["row"]["version"])}</span></div><div class="badges">{"".join(badges)}</div>'
            f'<div class="sub">{sub}</div></summary><div class="body">{problems}{fix}{reasons}{ev_html}{table}</div></details>')


def section(title, desc, items, count_key="left", open_cards=False):
    body = "".join(card(p, open_cards) for p in items) if items else '<p class="empty">해당 없음</p>'
    total = sum(len(p[count_key]) for p in items)
    return (f'<h2>{esc(title)} <span class="meta">{len(items)}개 패키지 · {total}건</span></h2>'
            f'<p class="meta">{esc(desc)}</p>{body}')


def boot_section(items, boot):
    if not items:
        return ""
    rows = "".join(
        f'<tr><td>{esc(p["pkg"].split(":")[1])}</td><td>{esc(p["row"]["version"])} → {esc(p["act"]["boot_managed"])}</td>'
        f'<td class="num">{len(p["vulns"])}건</td></tr>' for p in items)
    return (f'<h2>① Spring Boot 패치로 해결 <span class="meta">{len(items)}개 패키지 · '
            f'{sum(len(p["vulns"]) for p in items)}건</span></h2>'
            f'<p class="meta">build 파일의 Spring Boot 버전 한 줄({esc(boot["current"])} → {esc(boot["latest_patch"])})로 '
            f'함께 올라가 모든 취약점이 해결되는 패키지 (BOM 대조로 계산)</p>'
            f'<div class="card"><div class="body" style="border-top:0"><table><tr><th>패키지</th><th>버전</th>'
            f'<th>취약점</th></tr>{rows}</table></div></div>')


def scrub(text, s):
    """리포트에 로컬 절대경로가 남지 않게 레포 경로와 홈 경로를 지운다."""
    import os
    return text.replace(s["module"] + "/", "").replace(s["module"], ".").replace(os.path.expanduser("~"), "~")


def render(s):
    by_pkg = {}
    for v in s["vulns"]:
        by_pkg.setdefault(v["PkgName"], []).append(v)
    actions = s.get("actions", {})
    views = [package_view(r["package"], r, by_pkg.get(r["package"], []), s["results"][r["package"]],
                          actions.get(r["package"])) for r in s["packages"]]
    views.sort(key=lambda p: (SEV_ORDER.get(p["max_sev"], 9), -p["max_epss"]))

    by_boot = [p for p in views if not p["left"]]
    rest = [p for p in views if p["left"]]
    off = [p for p in rest if p["category"] == "C"]
    now = [p for p in rest if p["priority"] == "P1"]
    later = [p for p in rest if p["priority"] == "P2"]
    unknown = [p for p in rest if p["category"] == "?"]
    review = [p for p in views if p["res"].get("needs_review")]
    n = lambda items: sum(len(p["left"]) for p in items)  # noqa: E731
    solved_total = len(s["vulns"]) - n(views)
    urgent_count = sum(1 for p in now for v in p["left"] if v["Severity"] in ("CRITICAL", "HIGH") or v["kev"])

    boot = s["boot"]
    cross = [p for p in views if p["act"].get("cross_line") and p["category"] in ("A", "B")]
    line_note = ""
    if cross and boot["current"]:
        same = boot["current"] == boot["latest_patch"]
        line = ".".join(boot["current"].split(".")[:2])
        line_note = (f'<div class="callout warn"><b>버전 라인 한계</b> — 실행되는 패키지 {len(cross)}개({n(cross)}건)는 '
                     f'현재 라인에 수정 버전이 없고 더 높은 라인에서만 고쳐졌습니다. '
                     + (f'Spring Boot {esc(boot["current"])}는 {esc(line)} 라인의 마지막 패치라 Boot 패치로도 해결되지 않습니다. '
                        if same else "")
                     + '프레임워크 메이저/마이너 버전 전환 계획이 필요합니다.</div>')
    review_note = (f'<div class="callout warn">사람 검토 {len(review)}개 — 에이전트 판정이 근거 검증을 통과하지 못해 '
                   f'"실행됨"으로 되돌린 패키지입니다.</div>') if review else ""
    u = s["usage"]
    cost = f'LLM 호출 {u["calls"]}회 · ${u["usd"]}' if s["model"] else "LLM 판단 생략(규칙만)"
    boot_tile = (f'<div class="tile"><div class="l">Boot 패치 후 남는 것</div><div class="n">{n(views)}</div>'
                 f'<div class="s">{esc(boot["current"])} → {esc(boot["latest_patch"])}로 {solved_total}건 해결</div></div>'
                 if boot["current"] and boot["current"] != boot["latest_patch"] else
                 f'<div class="tile"><div class="l">Boot 최신 패치 사용 중</div><div class="n">{n(views)}</div>'
                 f'<div class="s">{esc(boot["current"] or "-")}</div></div>')

    return scrub(f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>공급망 리포트 · {esc(s["name"])}</title>
<style>{CSS}</style></head><body><main>
<h1>SW 공급망 취약점 리포트 · {esc(s["name"])}</h1>
<div class="meta">{esc(s["generated_at"])} · {esc(s["jar"])} · SBOM 구성요소 {s["sbom_components"]}개 ·
판정 모델 {esc(s["model"] or "-")} · {esc(cost)} · 소요 {s["elapsed_sec"]}초</div>
<div class="funnel">
<div class="tile"><div class="l">스캔된 취약점</div><div class="n">{len(s["vulns"])}</div><div class="s">{len(views)}개 패키지</div></div>
{boot_tile}
<div class="tile p1"><div class="l">지금 조치 (P1)</div><div class="n">{urgent_count}</div><div class="s">실행되며 CRITICAL/HIGH·KEV · {len(now)}개 패키지</div></div>
<div class="tile c"><div class="l">실행 안 됨 (C)</div><div class="n">{n(off)}</div><div class="s">{len(off)}개 패키지 · 근거 포함</div></div>
</div>
{line_note}{review_note}
{boot_section(by_boot, boot)}
{section("② 지금 조치", "Boot 패치 후에도 남고, 실제로 실행되며(A·B), CRITICAL/HIGH 또는 실제 악용(KEV)인 취약점이 있는 패키지", now, open_cards=True)}
{section("③ 다음 정기 업데이트", "실행되지만 남는 취약점이 MEDIUM 이하인 패키지", later)}
{section("실행 안 됨", "설정·구조상 취약 기능이 실행되지 않는다고 판단한 패키지 — 근거를 함께 확인하세요", off)}
{section("미판정", "규칙으로 정해지지 않았고 LLM 판단을 생략한 패키지", unknown) if unknown else ""}
<footer>사실(SBOM·CVE·EPSS·KEV·의존성 경로·소스/설정 검색)은 도구가, 실행 여부 판단은 에이전트가, 근거 인용 검증과 조치·우선순위 계산은 규칙이 담당합니다.
검증을 통과하지 못한 판정은 자동으로 "실행됨"으로 되돌립니다. "Boot 패치 후"는 Spring Boot BOM 대조로 계산한 예측이며,
업그레이드 과정에서 바뀌는 전이 의존성(예: 다른 좌표로 교체된 라이브러리)은 반영되지 않으므로 패치 후 재스캔으로 확인하세요.
판정 A=코드가 직접 사용 · B=프레임워크가 실행 · C=실행 안 됨.</footer>
</main></body></html>""", s)
