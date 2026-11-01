"""같은 설정의 반복 실행 결과를 라벨과 비교해 편차를 본다. usage: variance.py <labels.json> <judge1.json> <judge2.json> ..."""
import collections
import json
import sys

labels = {k: v for k, v in json.load(open(sys.argv[1])).items() if not k.startswith("_")}
runs = [json.load(open(p)) for p in sys.argv[2:]]
runs = [r["results"] if "results" in r else r for r in runs]  # run.py의 summary.json도 받는다
scores, dangerous, reviews = [], 0, 0
for run in runs:
    scores.append(sum(run[p]["result"]["category"] in lab["accept"] for p, lab in labels.items()))
    for p, lab in labels.items():
        r = run[p]["result"]
        dangerous += r["category"] == "C" and "C" not in lab["accept"]
        reviews += bool(r.get("needs_review"))
print(f"실행별 일치: {scores} / {len(labels)}  (위험한 오판 총 {dangerous}건, 검증 실패→B 폴백 총 {reviews}건)")
for p, lab in labels.items():
    cats = [run[p]["result"]["category"] for run in runs]
    pris = [run[p]["result"].get("priority", "-") for run in runs]
    acts = [str(run[p]["result"].get("action", "-")) for run in runs]
    stable = len(set(cats)) == 1
    hits = sum(c in lab["accept"] for c in cats)
    if not stable or hits < len(runs) or len(set(pris)) > 1:
        print(f"  {p.split(':')[1]:20} 정답 {'/'.join(lab['accept']):4} 분류 {''.join(cats)}  우선순위 {','.join(pris)}  조치 {''.join(acts)}")
