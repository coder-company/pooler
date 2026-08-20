#!/usr/bin/env python3
"""Create a deterministic gzip-compressed tar archive.

The release shell script prepares a small staging tree.  This helper owns the
archive details so that file order, metadata, and the gzip header are explicit
and identical on Linux and macOS.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path
import tarfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    return parser.parse_args()


def archive(root: Path, destination: Path, epoch: int) -> None:
    if epoch < 0:
        raise ValueError("archive epoch must not be negative")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"archive root is not a directory: {root}")

    entries = [root]
    entries.extend(sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()))

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        # Supplying mtime and an empty filename avoids wall-clock data in the
        # gzip header.  The tar stream below carries the same epoch.
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=output,
            mtime=epoch,
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path in entries:
                    relative = path.relative_to(root)
                    archive_name = root.name if not relative.parts else f"{root.name}/{relative.as_posix()}"
                    if path.is_symlink():
                        raise ValueError(f"release tree contains an unsupported symlink: {path}")
                    if path.is_dir():
                        info = tarfile.TarInfo(archive_name)
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        info.size = 0
                        info.mtime = epoch
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        tar.addfile(info)
                        continue
                    if not path.is_file():
                        raise ValueError(f"release tree contains a non-regular file: {path}")
                    data = path.read_bytes()
                    info = tarfile.TarInfo(archive_name)
                    info.type = tarfile.REGTYPE
                    info.mode = 0o755 if relative.parts and relative.parts[0] == "bin" else 0o644
                    info.size = len(data)
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tar.addfile(info, io.BytesIO(data))


def main() -> int:
    arguments = parse_args()
    archive(arguments.root, arguments.archive, arguments.epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
