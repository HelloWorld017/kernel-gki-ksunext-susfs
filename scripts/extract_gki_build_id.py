import argparse
import gzip
import re
import struct
import subprocess
from pathlib import Path


def extract_gki_build_id(boot: bytes) -> str:
    if len(boot) < 4096 or boot[:8] != b"ANDROID!":
        raise ValueError("expected an Android boot image")

    version = struct.unpack_from("<I", boot, 40)[0]
    if version not in (3, 4):
        raise ValueError(f"expected boot header v3 or v4, got v{version}")

    kernel_size = struct.unpack_from("<I", boot, 8)[0]
    if not kernel_size or 4096 + kernel_size > len(boot):
        raise ValueError("invalid kernel size in boot header")

    kernel = boot[4096 : 4096 + kernel_size]
    if kernel.startswith((b"\x02\x21\x4c\x18", b"\x04\x22\x4d\x18")):
        kernel = subprocess.run(
            ["lz4", "-d", "-c"], input=kernel, capture_output=True, check=True
        ).stdout

    elif kernel.startswith(b"\x1f\x8b"):
        kernel = gzip.decompress(kernel)

    # Android's kernel release embeds the CI build number as -ab<build ID>.
    ids = set(re.findall(rb"Linux version [^\s\x00]*-ab([0-9]+)(?=[^0-9]|$)", kernel))

    if len(ids) != 1:
        raise ValueError(
            f"expected one GKI build ID in kernel banner, found {len(ids)}"
        )
    return ids.pop().decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("boot", type=Path)
    args = parser.parse_args()
    print(extract_gki_build_id(args.boot.read_bytes()))


if __name__ == "__main__":
    main()
