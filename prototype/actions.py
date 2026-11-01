"""조치 유형을 LLM 없이 계산한다 — Spring Boot 최신 패치 BOM과 취약점 수정 버전을 대조.

1: Boot 패치 버전업으로 해결 / 2: Boot 관리 버전 오버라이드 / 3: 직접 선언한 상위 의존성 업그레이드 / 4: 개별 대응
"""
import json
import pathlib
import re
import subprocess
import xml.etree.ElementTree as ET

CENTRAL = "https://repo1.maven.org/maven2"
NS = {"m": "http://maven.apache.org/POM/4.0.0"}
CACHE = pathlib.Path(__file__).resolve().parent.parent / "runs" / "_cache" / "poms"


def fetch_pom(group, artifact, version):
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"{group}__{artifact}__{version}.pom"
    if not path.exists():
        url = f"{CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
        path.write_bytes(subprocess.run(["curl", "-sf", url], capture_output=True, check=True).stdout)
    return ET.parse(path).getroot()


def resolve(text, props):
    for _ in range(5):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), text)
        if new == text:
            break
        text = new
    return text


def bom_versions(group, artifact, version, depth=0):
    """BOM의 dependencyManagement를 import된 하위 BOM까지 펼쳐 {group:artifact: version}으로."""
    root = fetch_pom(group, artifact, version)
    props = {"project.version": version}
    for p in root.findall("m:properties/*", NS):
        props[p.tag.split("}")[1]] = (p.text or "").strip()
    managed = {}
    for d in root.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
        g = resolve(d.findtext("m:groupId", "", NS), props)
        a = resolve(d.findtext("m:artifactId", "", NS), props)
        v = resolve(d.findtext("m:version", "", NS), props)
        if d.findtext("m:scope", "", NS) == "import" and depth < 3:
            try:
                for k, val in bom_versions(g, a, v, depth + 1).items():
                    managed.setdefault(k, val)
            except subprocess.CalledProcessError:
                pass
        else:
            managed.setdefault(f"{g}:{a}", v)
    return managed


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def required_fix(installed, fixed_field):
    """여러 수정 버전 중 설치 버전과 같은 라인(major.minor)을 우선 고른다."""
    cands = [c.strip() for c in (fixed_field or "").split(",") if c.strip()]
    newer = [c for c in cands if vkey(c) > vkey(installed)]
    if not newer:
        return None
    same_line = [c for c in newer if vkey(c)[:2] == vkey(installed)[:2]]
    same_major = [c for c in newer if vkey(c)[:1] == vkey(installed)[:1]]
    return min(same_line or same_major or newer, key=vkey)


def plan(vulns, rows, boot_latest, pins):
    """패키지별 조치 계산. pins = build 파일에 버전을 직접 적은 의존성. 반환: {package: {...}}와 Boot 패치 후 남는 취약점 수."""
    bom = bom_versions("org.springframework.boot", "spring-boot-dependencies", boot_latest) if boot_latest else {}
    out, remaining = {}, 0
    for row in rows:
        pkg = row["package"]
        pv = [v for v in vulns if v["PkgName"] == pkg]
        needs = [required_fix(v["InstalledVersion"], v.get("FixedVersion")) for v in pv]
        target = max((n for n in needs if n), key=vkey, default=None)
        managed = bom.get(pkg)
        solved = [v["VulnerabilityID"] for v, n in zip(pv, needs) if n and managed and vkey(managed) >= vkey(n)]
        solved_by_boot = len(solved)
        remaining += len(pv) - solved_by_boot
        pinned_roots = [r for r in row["via"] if r in pins]
        if target is None:
            action, fix = 4, "수정 버전이 아직 없음 — 공지 모니터링, 필요 시 완화 조치"
        elif managed and solved_by_boot == len(pv):
            action, fix = 1, f"Spring Boot {boot_latest} 패치 버전업으로 해결 (Boot 관리 버전 {managed})"
        elif managed and vkey(target)[:2] != vkey(row["version"])[:2]:
            # 같은 라인(major.minor)에 수정 버전이 없음 — 오버라이드로 끝나는 일이 아니다
            action = 2
            fix = (f"같은 {'.'.join(map(str, vkey(row['version'])[:2]))} 라인에 수정 버전 없음 → {target}는 라인이 바뀌는 "
                   f"업그레이드라 프레임워크 버전 전환과 함께 검토 필요 (Boot 패치로 {solved_by_boot}/{len(pv)}건 해결)")
        elif managed:
            action = 2
            fix = (f"Boot {boot_latest}도 {managed}까지만 올림 → {pkg.split(':')[1]}를 {target} 이상으로 버전 오버라이드"
                   f" (Boot 패치로 {solved_by_boot}/{len(pv)}건 해결)")
        elif pinned_roots:
            action = 3
            fix = (f"build 파일에 버전을 직접 적은 {', '.join(f'{r}:{pins[r]}' for r in pinned_roots)}를 "
                   f"{pkg.split(':')[1]} {target} 이상을 쓰는 버전으로 업그레이드")
        else:
            action, fix = 4, f"Boot 관리 대상 아님 — {pkg.split(':')[1]}를 {target} 이상으로 의존성 제약(constraint) 추가"
        cross_line = bool(target) and vkey(target)[:2] != vkey(row["version"])[:2]
        out[pkg] = {"action": action, "fix": fix, "target": target, "boot_managed": managed, "cross_line": cross_line,
                    "solved_by_boot": solved_by_boot, "solved_ids": solved}
    return out, remaining


if __name__ == "__main__":
    import sys
    summary = json.load(open(sys.argv[1]))
    import buildtool
    module = pathlib.Path(summary["module"])
    pins = buildtool.pinned_versions(module, summary.get("build_tool", "gradle"))
    result, remaining = plan(summary["vulns"], summary["packages"], summary["boot"]["latest_patch"], pins)
    for pkg, a in sorted(result.items(), key=lambda x: x[1]["action"]):
        print(f"{a['action']} {pkg.split(':')[1]:26} {a['fix']}")
    print(f"\nBoot {summary['boot']['latest_patch']} 패치 후 남는 취약점 예측: {remaining} / {len(summary['vulns'])}")
