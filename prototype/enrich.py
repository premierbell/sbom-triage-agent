"""trivy 결과에 EPSS(악용 확률)·KEV(실제 악용 여부)를 붙여 요약한다."""
import json
import subprocess
import sys

def load_vulns(path):
    d = json.load(open(path))
    return [v for r in d.get("Results", []) for v in (r.get("Vulnerabilities") or [])]

def fetch_epss(cves):
    scores = {}
    cves = sorted(c for c in cves if c.startswith("CVE-"))
    for i in range(0, len(cves), 80):
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 80])
        for row in json.loads(subprocess.check_output(["curl", "-sf", url]))["data"]:
            scores[row["cve"]] = float(row["epss"])
    return scores

def enrich(trivy_path, kev_path):
    vulns = load_vulns(trivy_path)
    kev = {v["cveID"] for v in json.load(open(kev_path))["vulnerabilities"]}
    epss = fetch_epss({v["VulnerabilityID"] for v in vulns})
    for v in vulns:
        v["epss"] = epss.get(v["VulnerabilityID"])
        v["kev"] = v["VulnerabilityID"] in kev
    return vulns

def main(trivy_path, kev_path):
    vulns = enrich(trivy_path, kev_path)
    crit_high = [v for v in vulns if v["Severity"] in ("CRITICAL", "HIGH")]
    print(f"{trivy_path}: 전체 {len(vulns)}건 / CRITICAL+HIGH {len(crit_high)}건")
    print(f"  KEV 포함 {sum(v['kev'] for v in vulns)}건")
    for th in (0.1, 0.01):
        print(f"  EPSS >= {th}: {sum(1 for v in vulns if (v['epss'] or 0) >= th)}건")
    print(f"  EPSS 없음(GHSA 등): {sum(1 for v in vulns if v['epss'] is None)}건")
    top = sorted(vulns, key=lambda v: -(v["epss"] or 0))[:5]
    for v in top:
        print(f"    {v['VulnerabilityID']} {v['PkgName']} {v['Severity']} epss={v['epss']} kev={v['kev']}")
    json.dump(vulns, open(trivy_path.replace(".trivy.json", ".enriched.json"), "w"), ensure_ascii=False, indent=1)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
