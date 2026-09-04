#!/usr/bin/env python3
"""Materialize Joint Benchmark Runner / Evaluation Harness v0.1 from staged archive parts."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
from pathlib import Path
import zipfile

EXPECTED_ZIP_SHA256 = "b3b0e074c28c30714224157c6b4f8a5dc9a15f5c03e973c058efcd44b8e5c379"
PART_COUNT = 8
PARTS_DIR = Path(__file__).resolve().parent / "staged_archive_parts"
ARCHIVE_PREFIX = "joint_benchmark_runner_v0_1/"


def _safe_target(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    root_resolved = root.resolve()
    if os.path.commonpath([str(root_resolved), str(target)]) != str(root_resolved):
        raise RuntimeError(f"unsafe archive path: {relative}")
    return target


def _load_archive() -> bytes:
    chunks: list[str] = []
    for index in range(PART_COUNT):
        path = PARTS_DIR / f"part-{index:02d}.b64"
        if not path.exists():
            raise SystemExit(f"missing staged archive part: {path}")
        chunks.append(path.read_text(encoding="utf-8").strip())
    raw = base64.b64decode("".join(chunks), validate=True)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != EXPECTED_ZIP_SHA256:
        raise SystemExit(
            "archive integrity failure: "
            f"expected={EXPECTED_ZIP_SHA256} actual={actual}"
        )
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize the staged v0.1 benchmark package"
    )
    parser.add_argument(
        "--extract",
        type=Path,
        default=Path("."),
        help="destination root (default: current directory)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing files such as README.md",
    )
    args = parser.parse_args()

    raw = _load_archive()
    root = args.extract.resolve()
    root.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        for info in archive.infolist():
            name = info.filename
            if not name.startswith(ARCHIVE_PREFIX):
                raise SystemExit(f"unexpected archive member outside prefix: {name}")
            relative = name[len(ARCHIVE_PREFIX):]
            if not relative:
                continue

            target = _safe_target(root, relative)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and not args.force:
                raise SystemExit(
                    f"refusing to overwrite {target}; rerun with --force"
                )
            target.write_bytes(archive.read(info))
            written.append(relative)

    print(f"archive_sha256={EXPECTED_ZIP_SHA256}")
    print(f"files_written={len(written)}")
    for relative in written:
        print(relative)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
