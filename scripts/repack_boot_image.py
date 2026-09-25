#!/usr/bin/env python3
"""
repack_boot_image.py

Pixel stock boot.img를 템플릿으로 사용해 kernel만 Image.lz4로 교체한다.
magiskboot / mkbootimg / avbtool 불필요.

전제:
- Android boot header v4
- ramdisk_size == 0 (Pixel GKI boot)
- stock boot.img 끝에 AVB footer(AVBf)가 존재
- bootloader unlocked

동작:
1. stock header page(4096 bytes)를 그대로 보존
2. header의 kernel_size만 새 Image.lz4 크기로 변경
3. 새 kernel 뒤의 padding을 4096-byte alignment로 배치
4. stock boot signature(존재하는 경우)와 outer vbmeta blob을 그대로 복사
5. stock partition size(파일 크기)를 그대로 유지
6. AVB footer의 original_image_size/vbmeta_offset만 새 payload 끝으로 갱신

주의:
- boot signature 및 vbmeta 내부 hash descriptor/signature는 stock 내용 그대로이므로 새 kernel에 대해
  cryptographically valid하지 않다.
- unlocked bootloader용이다.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
AVB_FOOTER_MAGIC = b"AVBf"
AVB_FOOTER_SIZE = 64
PAGE_SIZE = 4096


def align_up(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def die(msg: str) -> None:
    raise SystemExit(f"ERROR: {msg}")


def kernel_format(data: bytes) -> str:
    if data.startswith(b"\x02\x21\x4c\x18"):
        return "lz4_legacy"
    if data.startswith(b"\x04\x22\x4d\x18"):
        return "lz4_frame"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"MZ"):
        return "raw"
    return "unknown"


def parse_footer(img: bytes):
    if len(img) < AVB_FOOTER_SIZE:
        die("stock image too small")
    raw = img[-AVB_FOOTER_SIZE:]
    magic, major, minor, orig_size, vbmeta_off, vbmeta_size, reserved = struct.unpack(
        ">4sIIQQQ28s", raw
    )
    if magic != AVB_FOOTER_MAGIC:
        die("stock image has no AVB footer at EOF")
    if vbmeta_off + vbmeta_size > len(img) - AVB_FOOTER_SIZE:
        die("stock AVB footer points outside the image")
    if orig_size > vbmeta_off:
        die("stock AVB original image overlaps vbmeta")
    if img[vbmeta_off:vbmeta_off + 4] != b"AVB0":
        die("stock vbmeta does not start with AVB0")
    return {
        "major": major,
        "minor": minor,
        "original_image_size": orig_size,
        "vbmeta_offset": vbmeta_off,
        "vbmeta_size": vbmeta_size,
        "reserved": reserved,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stock_boot", type=Path)
    ap.add_argument("kernel_lz4", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument(
        "--allow-non-lz4",
        action="store_true",
        help="Image.lz4가 아니어도 허용 (권장하지 않음)",
    )
    args = ap.parse_args()

    stock = args.stock_boot.read_bytes()
    kernel = args.kernel_lz4.read_bytes()

    if len(stock) < PAGE_SIZE + AVB_FOOTER_SIZE:
        die("stock boot.img is too small for a header and AVB footer")
    if stock[:8] != BOOT_MAGIC:
        die("stock boot.img has no ANDROID! magic")

    kernel_size_old = struct.unpack_from("<I", stock, 8)[0]
    ramdisk_size = struct.unpack_from("<I", stock, 12)[0]
    header_size = struct.unpack_from("<I", stock, 20)[0]
    header_version = struct.unpack_from("<I", stock, 40)[0]

    if header_version != 4:
        die(f"expected boot header v4, got v{header_version}")
    if header_size != 1584:
        die(f"unexpected header_size={header_size}, expected 1584")
    if ramdisk_size != 0:
        die(f"expected ramdisk_size=0, got {ramdisk_size}")
    if not kernel or len(kernel) > 0xFFFFFFFF:
        die("new kernel size must fit in a nonzero 32-bit field")

    fmt = kernel_format(kernel)
    if fmt != "lz4_legacy" and not args.allow_non_lz4:
        die(f"new kernel format is {fmt}; expected lz4_legacy")

    footer = parse_footer(stock)
    stock_vbmeta = stock[
        footer["vbmeta_offset"]:
        footer["vbmeta_offset"] + footer["vbmeta_size"]
    ]
    signature_size = struct.unpack_from("<I", stock, 1580)[0]
    signature_offset_old = align_up(PAGE_SIZE + kernel_size_old, PAGE_SIZE)
    signature_end_old = signature_offset_old + signature_size
    if signature_end_old > footer["original_image_size"]:
        die("stock kernel or boot signature extends past the original image")
    signature = stock[signature_offset_old:signature_end_old]

    signature_offset_new = align_up(PAGE_SIZE + len(kernel), PAGE_SIZE)
    original_size_new = align_up(signature_offset_new + signature_size, PAGE_SIZE)
    vbmeta_offset_new = original_size_new
    if vbmeta_offset_new + len(stock_vbmeta) > len(stock) - AVB_FOOTER_SIZE:
        die("new kernel and vbmeta do not fit in the stock boot partition")

    packed = bytearray(len(stock))
    packed[:PAGE_SIZE] = stock[:PAGE_SIZE]
    struct.pack_into("<I", packed, 8, len(kernel))
    packed[PAGE_SIZE:PAGE_SIZE + len(kernel)] = kernel
    packed[signature_offset_new:signature_offset_new + signature_size] = signature
    packed[vbmeta_offset_new:vbmeta_offset_new + len(stock_vbmeta)] = stock_vbmeta
    packed[-AVB_FOOTER_SIZE:] = struct.pack(
        ">4sIIQQQ28s",
        AVB_FOOTER_MAGIC,
        footer["major"],
        footer["minor"],
        original_size_new,
        vbmeta_offset_new,
        footer["vbmeta_size"],
        footer["reserved"],
    )

    args.output.write_bytes(packed)
    print(f"Stock kernel: {kernel_size_old:,} bytes")
    print(f"New kernel:   {len(kernel):,} bytes ({fmt}, sha256 {sha256(kernel)})")
    print(f"Packed boot:  {len(packed):,} bytes ({args.output})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
