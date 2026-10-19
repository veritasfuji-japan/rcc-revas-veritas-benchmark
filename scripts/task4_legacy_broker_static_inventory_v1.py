"""Print a pinned, source-only legacy Broker inventory. Never import target code.

This is an audit aid, not an execution gate or complete Python call-graph proof.
Run from the repository root. Output goes only to stdout.
"""
import argparse
import ast
import hashlib
import io
import json
import subprocess
import tarfile

BASE = "f20fdd26234116a4981a27b8ef5f00881e236bf0"
TARGET = "scripts.task4_458_local_broker_once_ciphertext_v1"


def inventory(ref=BASE):
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", ref + "^{commit}"], text=True).strip()
    archive = subprocess.check_output(["git", "archive", commit])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        files = {m.name: tar.extractfile(m).read()
                 for m in tar.getmembers() if m.isfile()}
    modules = {p[:-3].replace("/", "."): p for p in files if p.endswith(".py")}
    trees = {p: ast.parse(files[p].decode("utf8"), filename=p)
             for p in modules.values()}
    graph = {p: set() for p in trees}
    direct = []
    for path, tree in sorted(trees.items()):
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                names = [prefix] + [prefix + "." + a.name for a in node.names]
                for a in node.names:
                    if prefix + "." + a.name == TARGET:
                        aliases[a.asname or a.name] = ""
                    elif prefix == TARGET:
                        aliases[a.asname or a.name] = a.name
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
                for a in node.names:
                    if a.name == TARGET:
                        aliases[a.asname or a.name] = ""
            else:
                continue
            graph[path].update(modules[n] for n in names if n in modules)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            expression = ast.unparse(node.func)
            member = None
            for alias, imported_member in aliases.items():
                if imported_member and expression == alias:
                    member = imported_member
                elif not imported_member and expression.startswith(alias + "."):
                    member = expression[len(alias) + 1:]
            if path == modules[TARGET] and isinstance(node.func, ast.Name):
                member = node.func.id
            if member in {"action", "spawn_server", "Broker", "main", "run_demo"}:
                direct.append({"path": path, "line": node.lineno,
                               "expression": expression, "member": member})
    reachable = {modules[TARGET]}
    while True:
        expanded = reachable | {p for p, deps in graph.items() if deps & reachable}
        if expanded == reachable:
            break
        reachable = expanded
    workflows = []
    for path, raw in sorted(files.items()):
        if not path.startswith(".github/workflows/"):
            continue
        text = raw.decode("utf8")
        refs = [p for p in sorted(reachable)
                if p in text or p[:-3].replace("/", ".") in text]
        if refs:
            workflows.append({"path": path, "textual_module_references": refs})
    mentions = []
    for path, raw in sorted(files.items()):
        try:
            lines = raw.decode("utf8").splitlines()
        except UnicodeDecodeError:
            continue
        hits = [i for i, line in enumerate(lines, 1)
                if "task4_458" in line.lower() or "task4-458" in line.lower()]
        if hits:
            mentions.append({"path": path, "lines": hits})
    relevant = reachable | {x["path"] for x in workflows + mentions}
    return {
        "schema": "task4.legacy-broker.static-inventory.v1",
        "audited_commit": commit,
        "scope": "all tracked regular Python files; workflow/text reference inventory",
        "python_files_parsed": len(trees),
        "target_code_imported_or_executed": False,
        "runtime_reachability_proven": False,
        "global_no_legacy_listener_proven": False,
        "production_bypass_resistance_proven": False,
        "provider_authorized": False,
        "direct_syntactic_call_sites": sorted(direct, key=lambda x: (x["path"], x["line"])),
        "transitive_import_candidates_not_runtime_proof": sorted(reachable),
        "workflow_text_candidates_not_dispatch_proof": workflows,
        "literal_references_including_pins_and_docs": mentions,
        "relevant_file_sha256": {p: hashlib.sha256(files[p]).hexdigest()
                                 for p in sorted(relevant)},
        "limitations": [
            "Import closure overapproximates execution, including function-local imports.",
            "Alias matching is syntactic and not scope-sensitive; manual review required.",
            "Dynamic imports, reflection, forwarded aliases and injected callbacks are not resolved.",
            "Workflow references include path filters; generic pytest collection needs manual review.",
            "CLI/function existence is not proof of a running listener or successful exploit.",
            "No runtime Provider, SDK, network, credential or security boundary test is performed."
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default=BASE)
    print(json.dumps(inventory(parser.parse_args().ref), indent=2, sort_keys=True))
