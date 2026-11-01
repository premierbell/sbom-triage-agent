"""judge 결과를 사람이 고정한 라벨과 비교한다. usage: evaluate.py <judge.json> <labels.json>"""
import json
import sys

judged = json.load(open(sys.argv[1]))
labels = {k: v for k, v in json.load(open(sys.argv[2])).items() if not k.startswith("_")}
hit = 0
for pkg, lab in labels.items():
    got = judged[pkg]["result"]["category"]
    ok = got in lab["accept"]
    hit += ok
    if not ok:
        print(f"  MISS {pkg.split(':')[1]:20} 정답 {'/'.join(lab['accept'])} ← 에이전트 {got}")
print(f"분류 일치 {hit}/{len(labels)}")
