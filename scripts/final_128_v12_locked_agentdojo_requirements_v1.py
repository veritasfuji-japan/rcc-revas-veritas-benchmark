#!/usr/bin/env python3
import argparse
import tomllib
from pathlib import Path

PRESERVED = {
    "openai": "1.109.1",
    "pydantic": "2.11.10",
    "idna": "3.15",
    "httpx": "0.28.1",
    "requests": "2.34.2",
    "pyyaml": "6.0.3",
}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lock", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    data = tomllib.loads(Path(args.lock).read_text())
    packages = data["package"]
    roots = [x for x in packages if x.get("name") == "agentdojo"]
    assert len(roots) == 1
    root = roots[0]

    by_name = {}
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", {})
        if name and version and "registry" in source:
            by_name.setdefault(name, set()).add(version)

    reqs = []
    seen = set()
    for dep in root["dependencies"]:
        name = dep["name"]
        if name in PRESERVED:
            version = PRESERVED[name]
        else:
            versions = by_name.get(name, set())
            if len(versions) != 1:
                raise SystemExit(f"LOCK_VERSION_AMBIGUOUS:{name}:{sorted(versions)}")
            version = next(iter(versions))
        extras = dep.get("extra", [])
        rendered = name
        if extras:
            rendered += "[" + ",".join(extras) + "]"
        reqs.append(f"{rendered}=={version}")
        seen.add(name)

    # Preserve the bounded V11 transport/runtime packages even when they are
    # only transitively imported by the AgentDojo import chain.
    for name in ("idna", "httpx", "requests"):
        if name not in seen:
            reqs.append(f"{name}=={PRESERVED[name]}")

    out = Path(args.output)
    out.write_text("\n".join(sorted(reqs)) + "\n")
    print("PASS_V12_LOCKED_DIRECT_REQUIREMENTS_EMITTED")
    for r in sorted(reqs):
        print(f"REQ {r}")

if __name__ == "__main__":
    main()
