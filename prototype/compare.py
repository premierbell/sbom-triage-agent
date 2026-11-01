"""두 시점의 runs 결과(summary.json)를 레포별로 비교한다: 시간·LLM 호출·비용·라벨 일치·판정 주체.

usage: compare.py <이전 runs 디렉토리> <이후 runs 디렉토리>
"""
import collections
import json
import pathlib
import sys

LABELS = {"world-engine": "labels_we.json", "team3": "labels_t3.json", "team4": "labels_t4.json"}
HERE = pathlib.Path(__file__).parent


def score(summary, name):
    if name not in LABELS:
        return "-"
    labels = {k: v for k, v in json.loads((HERE / LABELS[name]).read_text()).items() if not k.startswith("_")}
    results = summary["results"]
    hit = sum(results[p]["result"]["category"] in lab["accept"] for p, lab in labels.items() if p in results)
    danger = sum(results[p]["result"]["category"] == "C" and "C" not in lab["accept"]
                 for p, lab in labels.items() if p in results)
    return f"{hit}/{len(labels)} (위험 {danger})"


def deciders(summary):
    c = collections.Counter()
    for r in summary["results"].values():
        by = r["result"].get("decided_by", "llm")
        c["규칙" if by.startswith("rule") else "에이전트"] += 1
    return f'규칙 {c["규칙"]} · 에이전트 {c["에이전트"]}'


def main(before_dir, after_dir):
    print("| 레포 | 시간 | LLM 호출 | 비용 | 라벨 일치 | 판정 주체 |")
    print("|---|---|---|---|---|---|")
    totals = collections.Counter()
    for name in ["buzzerbidder", "world-engine", "team3", "team4"]:
        b = json.loads((pathlib.Path(before_dir) / name / "summary.json").read_text())
        a = json.loads((pathlib.Path(after_dir) / name / "summary.json").read_text())
        print(f'| {name} | {b["elapsed_sec"]}s → {a["elapsed_sec"]}s | {b["usage"]["calls"]} → {a["usage"]["calls"]} '
              f'| ${b["usage"]["usd"]} → ${a["usage"]["usd"]} | {score(b, name)} → {score(a, name)} '
              f'| {deciders(b)} → {deciders(a)} |')
        for k, s in (("b", b), ("a", a)):
            totals[k + "sec"] += s["elapsed_sec"]
            totals[k + "calls"] += s["usage"]["calls"]
            totals[k + "usd"] += s["usage"]["usd"]
    print(f'| 합계 | {totals["bsec"]}s → {totals["asec"]}s | {totals["bcalls"]} → {totals["acalls"]} '
          f'| ${totals["busd"]:.2f} → ${totals["ausd"]:.2f} | | |')


if __name__ == "__main__":
    main(*sys.argv[1:3])
