#!/usr/bin/env python3
"""
bootimg_diff.py - Android boot.img v3/v4 / AVB 구조 비교 도구

목적:
  - Pixel/GKI boot.img 두 개를 구조 단위로 dissect
  - boot header, kernel, ramdisk, v4 boot signature, padding,
    AVB footer, embedded vbmeta 및 hash descriptor 비교
  - 이미지 크기 차이가 단순 zero padding인지 AVB layout 차이인지 확인
  - 외부 Python 패키지 없이 동작

사용 예:
  python bootimg_diff.py boot.original.img boot-lz4.img
  python bootimg_diff.py boot.original.img boot-lz4.img --extract out
  python bootimg_diff.py boot.original.img boot-lz4.img --json report.json

선택사항:
  PATH에 avbtool이 있으면 --run-avbtool 로 avbtool info_image 결과도 덧붙입니다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional

BOOT_MAGIC = b"ANDROID!"
PAGE = 4096
BOOT_HEADER_V3_SIZE = 1580
BOOT_HEADER_V4_SIZE = 1584
AVB_FOOTER_MAGIC = b"AVBf"
AVB_FOOTER_SIZE = 64
AVB_VBMETA_MAGIC = b"AVB0"
AVB_VBMETA_HEADER_SIZE = 256
AVB_DESCRIPTOR_TAG_PROPERTY = 0
AVB_DESCRIPTOR_TAG_HASHTREE = 1
AVB_DESCRIPTOR_TAG_HASH = 2
AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE = 3
AVB_DESCRIPTOR_TAG_CHAIN_PARTITION = 4


def align_up(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_ascii(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def human(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    x = float(n)
    for u in units:
        if x < 1024 or u == units[-1]:
            return f"{x:.2f} {u}" if u != "B" else f"{int(x)} B"
        x /= 1024
    return f"{n} B"


def hex_preview(data: bytes, n: int = 32) -> str:
    return data[:n].hex(" ")


def classify_kernel(data: bytes) -> str:
    if data.startswith(b"\x02\x21\x4c\x18"):
        return "lz4_legacy"
    if data.startswith(b"\x04\x22\x4d\x18"):
        return "lz4_frame"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"MZ"):
        return "raw/PE-stub (ARM64 Image 가능성 높음)"
    return "unknown"


def decode_os_version_patch(v: int) -> dict[str, Any]:
    a = (v >> 25) & 0x7F
    b = (v >> 18) & 0x7F
    c = (v >> 11) & 0x7F
    year = ((v >> 4) & 0x7F) + 2000
    month = v & 0x0F
    return {
        "raw": v,
        "os_version": f"{a}.{b}.{c}",
        "os_patch_level": f"{year:04d}-{month:02d}" if month else f"{year:04d}-00",
    }


@dataclass
class Region:
    name: str
    offset: int
    size: int
    sha256: str = ""
    all_zero: bool = False
    first_bytes: str = ""

    def finish(self, blob: bytes) -> None:
        d = blob[self.offset:self.offset + self.size]
        self.sha256 = sha256(d)
        self.all_zero = bool(d) and not any(d)
        self.first_bytes = hex_preview(d)


def parse_boot_header(data: bytes) -> dict[str, Any]:
    if len(data) < BOOT_HEADER_V3_SIZE:
        raise ValueError("파일이 boot header보다 작습니다.")
    if data[:8] != BOOT_MAGIC:
        raise ValueError(f"ANDROID! magic이 없습니다: {data[:8]!r}")

    kernel_size = struct.unpack_from("<I", data, 8)[0]
    ramdisk_size = struct.unpack_from("<I", data, 12)[0]
    osver_patch = struct.unpack_from("<I", data, 16)[0]
    header_size = struct.unpack_from("<I", data, 20)[0]
    reserved = list(struct.unpack_from("<4I", data, 24))
    header_version = struct.unpack_from("<I", data, 40)[0]
    cmdline = printable_ascii(data[44:44 + 1536])

    if header_version not in (3, 4):
        raise ValueError(f"이 스크립트는 boot header v3/v4 중심입니다. 감지 버전: {header_version}")

    signature_size = 0
    if header_version >= 4:
        if len(data) < BOOT_HEADER_V4_SIZE:
            raise ValueError("v4 header가 잘렸습니다.")
        signature_size = struct.unpack_from("<I", data, 1580)[0]

    kernel_off = PAGE
    kernel_end = kernel_off + kernel_size
    ramdisk_off = align_up(kernel_end, PAGE)
    ramdisk_end = ramdisk_off + ramdisk_size
    signature_off = align_up(ramdisk_end, PAGE)
    signature_end = signature_off + signature_size
    payload_end_aligned = align_up(signature_end, PAGE)

    return {
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "os_version_patch": decode_os_version_patch(osver_patch),
        "header_size": header_size,
        "reserved": reserved,
        "header_version": header_version,
        "cmdline": cmdline,
        "signature_size": signature_size,
        "page_size": PAGE,
        "kernel_offset": kernel_off,
        "kernel_end": kernel_end,
        "ramdisk_offset": ramdisk_off,
        "ramdisk_end": ramdisk_end,
        "signature_offset": signature_off,
        "signature_end": signature_end,
        "payload_end_aligned": payload_end_aligned,
    }


def parse_avb_footer(data: bytes) -> Optional[dict[str, Any]]:
    if len(data) < AVB_FOOTER_SIZE:
        return None
    f = data[-AVB_FOOTER_SIZE:]
    if f[:4] != AVB_FOOTER_MAGIC:
        return None
    _, maj, min_, orig_size, vbmeta_off, vbmeta_size, _ = struct.unpack(
        ">4sIIQQQ28s", f
    )
    valid_range = vbmeta_off + vbmeta_size <= len(data) - AVB_FOOTER_SIZE
    return {
        "offset": len(data) - AVB_FOOTER_SIZE,
        "version_major": maj,
        "version_minor": min_,
        "original_image_size": orig_size,
        "vbmeta_offset": vbmeta_off,
        "vbmeta_size": vbmeta_size,
        "range_valid": valid_range,
    }


def parse_hash_descriptor(desc: bytes) -> Optional[dict[str, Any]]:
    modern_fmt = ">QQQ32sIIII60s"
    modern_size = struct.calcsize(modern_fmt)
    if len(desc) < modern_size:
        return None
    try:
        tag, nfollow, image_size, alg_raw, name_len, salt_len, digest_len, flags, _ = struct.unpack_from(modern_fmt, desc, 0)
    except struct.error:
        return None
    if tag != AVB_DESCRIPTOR_TAG_HASH:
        return None
    p = modern_size
    needed = p + name_len + salt_len + digest_len
    if needed > len(desc):
        return None
    name = desc[p:p + name_len]
    p += name_len
    salt = desc[p:p + salt_len]
    p += salt_len
    digest = desc[p:p + digest_len]
    return {
        "type": "hash",
        "tag": tag,
        "num_bytes_following": nfollow,
        "image_size": image_size,
        "hash_algorithm": printable_ascii(alg_raw),
        "partition_name": name.decode("utf-8", errors="replace"),
        "salt": salt.hex(),
        "digest": digest.hex(),
        "flags": flags,
    }


def parse_descriptors(vbmeta: bytes, h: dict[str, Any]) -> list[dict[str, Any]]:
    auth_size = h["authentication_data_block_size"]
    start = AVB_VBMETA_HEADER_SIZE + auth_size + h["descriptors_offset"]
    end = start + h["descriptors_size"]
    if end > len(vbmeta) or start > end:
        return [{"error": "descriptor range가 vbmeta 범위를 벗어납니다."}]
    out = []
    pos = start
    while pos + 16 <= end:
        tag, nfollow = struct.unpack_from(">QQ", vbmeta, pos)
        total = 16 + nfollow
        if total < 16 or pos + total > end:
            out.append({"offset_in_vbmeta": pos, "tag": tag, "num_bytes_following": nfollow, "error": "descriptor size 범위 오류"})
            break
        raw = vbmeta[pos:pos + total]
        item = {
            "offset_in_vbmeta": pos,
            "tag": tag,
            "num_bytes_following": nfollow,
            "sha256": sha256(raw),
        }
        if tag == AVB_DESCRIPTOR_TAG_HASH:
            parsed = parse_hash_descriptor(raw)
            item.update(parsed or {"type": "hash(unparsed)"})
        elif tag == AVB_DESCRIPTOR_TAG_HASHTREE:
            item["type"] = "hashtree"
        elif tag == AVB_DESCRIPTOR_TAG_PROPERTY:
            item["type"] = "property"
        elif tag == AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE:
            item["type"] = "kernel_cmdline"
        elif tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION:
            item["type"] = "chain_partition"
        else:
            item["type"] = "unknown"
        out.append(item)
        pos += total
    return out


def parse_vbmeta(blob: bytes, absolute_offset: int = 0) -> Optional[dict[str, Any]]:
    if len(blob) < AVB_VBMETA_HEADER_SIZE or blob[:4] != AVB_VBMETA_MAGIC:
        return None
    try:
        h = {
            "absolute_offset": absolute_offset,
            "required_libavb_version_major": struct.unpack_from(">I", blob, 4)[0],
            "required_libavb_version_minor": struct.unpack_from(">I", blob, 8)[0],
            "authentication_data_block_size": struct.unpack_from(">Q", blob, 12)[0],
            "auxiliary_data_block_size": struct.unpack_from(">Q", blob, 20)[0],
            "algorithm_type": struct.unpack_from(">I", blob, 28)[0],
            "hash_offset": struct.unpack_from(">Q", blob, 32)[0],
            "hash_size": struct.unpack_from(">Q", blob, 40)[0],
            "signature_offset": struct.unpack_from(">Q", blob, 48)[0],
            "signature_size": struct.unpack_from(">Q", blob, 56)[0],
            "public_key_offset": struct.unpack_from(">Q", blob, 64)[0],
            "public_key_size": struct.unpack_from(">Q", blob, 72)[0],
            "public_key_metadata_offset": struct.unpack_from(">Q", blob, 80)[0],
            "public_key_metadata_size": struct.unpack_from(">Q", blob, 88)[0],
            "descriptors_offset": struct.unpack_from(">Q", blob, 96)[0],
            "descriptors_size": struct.unpack_from(">Q", blob, 104)[0],
            "rollback_index": struct.unpack_from(">Q", blob, 112)[0],
            "flags": struct.unpack_from(">I", blob, 120)[0],
            "rollback_index_location": struct.unpack_from(">I", blob, 124)[0],
            "release_string": printable_ascii(blob[128:176]),
        }
    except struct.error:
        return None
    total = AVB_VBMETA_HEADER_SIZE + h["authentication_data_block_size"] + h["auxiliary_data_block_size"]
    h["computed_vbmeta_size"] = total
    h["structurally_complete"] = total <= len(blob)
    sl = blob[:min(total, len(blob))]
    h["sha256"] = sha256(sl)
    h["descriptors"] = parse_descriptors(sl, h) if h["structurally_complete"] else []
    return h


def scan_magic(data: bytes, magic: bytes, limit: int = 200) -> list[int]:
    out, start = [], 0
    while len(out) < limit:
        p = data.find(magic, start)
        if p < 0:
            break
        out.append(p)
        start = p + 1
    return out


def trailing_zero_count(data: bytes) -> int:
    i = len(data)
    while i > 0 and data[i - 1] == 0:
        i -= 1
    return len(data) - i


def first_diff(a: bytes, b: bytes) -> Optional[int]:
    n = min(len(a), len(b))
    chunk = 1024 * 1024
    for base in range(0, n, chunk):
        aa = a[base:min(n, base + chunk)]
        bb = b[base:min(n, base + chunk)]
        if aa != bb:
            for i, (x, y) in enumerate(zip(aa, bb)):
                if x != y:
                    return base + i
    return n if len(a) != len(b) else None


def common_prefix_len(a: bytes, b: bytes) -> int:
    d = first_diff(a, b)
    return min(len(a), len(b)) if d is None else d


def common_suffix_len(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    matched = 0
    chunk = 1024 * 1024
    while matched < n:
        take = min(chunk, n - matched)
        aa = a[len(a)-matched-take:len(a)-matched]
        bb = b[len(b)-matched-take:len(b)-matched]
        if aa == bb:
            matched += take
            continue
        for i in range(1, take + 1):
            if aa[-i] != bb[-i]:
                return matched + i - 1
        matched += take
    return n


def describe_pages(data: bytes, start: int, page: int = PAGE) -> dict[str, Any]:
    start = max(0, min(start, len(data)))
    runs = []
    current = None
    run_start = start

    def cls(p: bytes) -> str:
        if not p:
            return "empty"
        if not any(p):
            return "zero"
        if AVB_VBMETA_MAGIC in p:
            return "contains_AVB0"
        if AVB_FOOTER_MAGIC in p:
            return "contains_AVBf"
        return "data"

    pos = start
    while pos < len(data):
        c = cls(data[pos:min(len(data), pos + page)])
        if current is None:
            current, run_start = c, pos
        elif c != current:
            runs.append({"kind": current, "offset": run_start, "end": pos, "size": pos-run_start})
            current, run_start = c, pos
        pos += page
    if current is not None:
        runs.append({"kind": current, "offset": run_start, "end": len(data), "size": len(data)-run_start})
    return {"start": start, "runs": runs}


def dissect(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    h = parse_boot_header(data)
    regions: list[Region] = []

    def add(name: str, off: int, size: int) -> None:
        if off < 0 or size < 0 or off > len(data):
            return
        r = Region(name, off, min(size, len(data)-off))
        r.finish(data)
        regions.append(r)

    add("header_page", 0, PAGE)
    add("kernel", h["kernel_offset"], h["kernel_size"])
    if h["ramdisk_offset"] > h["kernel_end"]:
        add("kernel_padding", h["kernel_end"], h["ramdisk_offset"]-h["kernel_end"])
    if h["ramdisk_size"]:
        add("ramdisk", h["ramdisk_offset"], h["ramdisk_size"])
    if h["signature_offset"] > h["ramdisk_end"]:
        add("ramdisk_padding", h["ramdisk_end"], h["signature_offset"]-h["ramdisk_end"])
    if h["signature_size"]:
        add("boot_signature", h["signature_offset"], h["signature_size"])
        if h["payload_end_aligned"] > h["signature_end"]:
            add("signature_padding", h["signature_end"], h["payload_end_aligned"]-h["signature_end"])

    footer = parse_avb_footer(data)
    body_end = footer["vbmeta_offset"] if footer and footer["range_valid"] else len(data)
    if body_end > h["payload_end_aligned"]:
        add("post_boot_payload_before_vbmeta", h["payload_end_aligned"], body_end-h["payload_end_aligned"])

    footer_vbmeta = None
    if footer and footer["range_valid"]:
        vo, vs = footer["vbmeta_offset"], footer["vbmeta_size"]
        add("footer_vbmeta", vo, vs)
        footer_vbmeta = parse_vbmeta(data[vo:vo+vs], vo)
        after = vo + vs
        if footer["offset"] > after:
            add("avb_padding_before_footer", after, footer["offset"]-after)
        add("avb_footer", footer["offset"], AVB_FOOTER_SIZE)

    boot_sig_vbmeta = None
    if h["signature_size"]:
        s, e = h["signature_offset"], h["signature_end"]
        boot_sig_vbmeta = parse_vbmeta(data[s:e], s)

    avb0 = scan_magic(data, AVB_VBMETA_MAGIC)
    avbf = scan_magic(data, AVB_FOOTER_MAGIC)
    all_vbmeta = []
    for p in avb0:
        v = parse_vbmeta(data[p:], p)
        if v:
            all_vbmeta.append(v)

    kern = data[h["kernel_offset"]:h["kernel_end"]]
    return {
        "path": str(path),
        "file_size": len(data),
        "file_size_human": human(len(data)),
        "sha256": sha256(data),
        "boot_header": h,
        "kernel_format": classify_kernel(kern),
        "kernel_first_bytes": hex_preview(kern, 16),
        "regions": [asdict(r) for r in regions],
        "avb_footer": footer,
        "footer_vbmeta": footer_vbmeta,
        "boot_signature_vbmeta": boot_sig_vbmeta,
        "all_vbmeta_candidates": all_vbmeta,
        "AVB0_positions": avb0,
        "AVBf_positions": avbf,
        "trailing_zero_bytes": trailing_zero_count(data),
        "tail_page_map": describe_pages(data, h["payload_end_aligned"]),
    }


def region_by_name(info: dict[str, Any], name: str) -> Optional[dict[str, Any]]:
    return next((r for r in info["regions"] if r["name"] == name), None)


def compare_infos(a: dict[str, Any], b: dict[str, Any], raw_a: bytes, raw_b: bytes) -> dict[str, Any]:
    c = {
        "file_size_delta_B_minus_A": b["file_size"] - a["file_size"],
        "whole_image_equal": a["sha256"] == b["sha256"],
        "common_prefix_bytes": common_prefix_len(raw_a, raw_b),
        "common_suffix_bytes": common_suffix_len(raw_a, raw_b),
        "first_whole_image_diff": first_diff(raw_a, raw_b),
        "header_field_differences": {},
        "region_differences": {},
    }
    fields = ["kernel_size","ramdisk_size","header_size","header_version","cmdline","signature_size","page_size","kernel_offset","ramdisk_offset","signature_offset","payload_end_aligned"]
    for k in fields:
        av, bv = a["boot_header"].get(k), b["boot_header"].get(k)
        if av != bv:
            c["header_field_differences"][k] = {"A": av, "B": bv}
    if a["boot_header"]["os_version_patch"] != b["boot_header"]["os_version_patch"]:
        c["header_field_differences"]["os_version_patch"] = {"A": a["boot_header"]["os_version_patch"], "B": b["boot_header"]["os_version_patch"]}

    names = sorted({r["name"] for r in a["regions"]} | {r["name"] for r in b["regions"]})
    for name in names:
        ar, br = region_by_name(a, name), region_by_name(b, name)
        if ar is None or br is None:
            c["region_differences"][name] = {"A": ar, "B": br, "note": "한 이미지에만 존재"}
            continue
        item = {
            "A_offset": ar["offset"], "B_offset": br["offset"],
            "A_size": ar["size"], "B_size": br["size"],
            "size_delta": br["size"] - ar["size"],
            "sha256_equal": ar["sha256"] == br["sha256"],
        }
        if not item["sha256_equal"]:
            aa = raw_a[ar["offset"]:ar["offset"]+ar["size"]]
            bb = raw_b[br["offset"]:br["offset"]+br["size"]]
            d = first_diff(aa, bb)
            item["first_diff_within_region"] = d
            if d is not None:
                item["A_first_diff_absolute"] = ar["offset"] + min(d, ar["size"])
                item["B_first_diff_absolute"] = br["offset"] + min(d, br["size"])
        c["region_differences"][name] = item
    return c


def extract_regions(info: dict[str, Any], raw: bytes, root: Path, label: str) -> None:
    d = root / label
    d.mkdir(parents=True, exist_ok=True)
    for r in info["regions"]:
        (d / f"{r['name']}.bin").write_bytes(raw[r["offset"]:r["offset"]+r["size"]])
    (d / "metadata.json").write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")


def run_avbtool(path: Path) -> Optional[str]:
    exe = shutil.which("avbtool")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "info_image", "--image", str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        return p.stdout
    except Exception as e:
        return f"avbtool 실행 실패: {e}"


def fmt_off(v: Optional[int]) -> str:
    return "-" if v is None else f"0x{v:x} ({v:,})"


def print_vbmeta(title: str, v: Optional[dict[str, Any]]) -> None:
    print(f"\n[{title}]")
    if not v:
        print("  없음 / AVB0로 시작하지 않음")
        return
    keys = ["absolute_offset","required_libavb_version_major","required_libavb_version_minor","authentication_data_block_size","auxiliary_data_block_size","algorithm_type","rollback_index","flags","rollback_index_location","release_string","computed_vbmeta_size","structurally_complete","sha256"]
    for k in keys:
        val = v.get(k)
        if k == "absolute_offset":
            val = fmt_off(val)
        print(f"  {k}: {val}")
    for i, d in enumerate(v.get("descriptors", [])):
        print(f"  descriptor[{i}]: {d}")


def print_info(label: str, i: dict[str, Any]) -> None:
    h = i["boot_header"]
    print("=" * 88)
    print(f"{label}: {i['path']}")
    print(f"size      : {i['file_size']:,} ({i['file_size_human']})")
    print(f"sha256    : {i['sha256']}")
    print(f"header    : v{h['header_version']}, header_size={h['header_size']}, page={h['page_size']}")
    print(f"kernel    : offset={fmt_off(h['kernel_offset'])}, size={h['kernel_size']:,}, fmt={i['kernel_format']}")
    print(f"ramdisk   : offset={fmt_off(h['ramdisk_offset'])}, size={h['ramdisk_size']:,}")
    print(f"signature : offset={fmt_off(h['signature_offset'])}, size={h['signature_size']:,}")
    print(f"payloadEnd: {fmt_off(h['payload_end_aligned'])}")
    print(f"cmdline   : {h['cmdline']!r}")
    print(f"os/patch  : {h['os_version_patch']}")
    print(f"kernel[0] : {i['kernel_first_bytes']}")
    print(f"AVB0 pos  : {[fmt_off(x) for x in i['AVB0_positions']]}")
    print(f"AVBf pos  : {[fmt_off(x) for x in i['AVBf_positions']]}")
    print(f"trail zero: {i['trailing_zero_bytes']:,}")
    print("\n[regions]")
    for r in i["regions"]:
        print(f"  {r['name']:<32} off={fmt_off(r['offset']):>22} size={r['size']:>10,} zero={str(r['all_zero']):<5} sha256={r['sha256'][:16]}…")
    print("\n[AVB footer]")
    if i["avb_footer"]:
        for k, v in i["avb_footer"].items():
            print(f"  {k}: {fmt_off(v) if k in ('offset','vbmeta_offset') else v}")
    else:
        print("  없음")
    print_vbmeta("v4 boot_signature 내부 vbmeta", i["boot_signature_vbmeta"])
    print_vbmeta("AVB footer가 가리키는 vbmeta", i["footer_vbmeta"])
    print("\n[payload 이후 page map]")
    for r in i["tail_page_map"]["runs"]:
        print(f"  {r['kind']:<15} {fmt_off(r['offset'])} .. {fmt_off(r['end'])} size={r['size']:,}")


def print_compare(c: dict[str, Any]) -> None:
    print("\n" + "#" * 88)
    print("COMPARISON")
    print("#" * 88)
    print(f"B - A file size : {c['file_size_delta_B_minus_A']:+,} bytes")
    print(f"whole equal     : {c['whole_image_equal']}")
    print(f"first diff      : {fmt_off(c['first_whole_image_diff'])}")
    print(f"common prefix   : {c['common_prefix_bytes']:,} bytes")
    print(f"common suffix   : {c['common_suffix_bytes']:,} bytes")
    print("\n[header field differences]")
    if not c["header_field_differences"]:
        print("  없음")
    else:
        for k, v in c["header_field_differences"].items():
            print(f"  {k}:\n    A: {v['A']}\n    B: {v['B']}")
    print("\n[region differences]")
    for name, d in c["region_differences"].items():
        if d.get("sha256_equal") is True and d.get("size_delta") == 0 and d.get("A_offset") == d.get("B_offset"):
            state = "IDENTICAL"
        elif d.get("sha256_equal") is True:
            state = "SAME_BYTES_DIFFERENT_LAYOUT"
        else:
            state = "DIFFERENT"
        print(f"  {name}: {state}")
        for k, v in d.items():
            print(f"    {k}: {v}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Android boot.img v3/v4 구조 및 AVB layout 비교")
    ap.add_argument("image_a", type=Path, help="기준 이미지 (예: boot.original.img)")
    ap.add_argument("image_b", type=Path, help="비교 이미지 (예: boot-lz4.img)")
    ap.add_argument("--extract", type=Path, help="각 section을 디렉터리에 추출")
    ap.add_argument("--json", type=Path, help="전체 분석 결과를 JSON으로 저장")
    ap.add_argument("--run-avbtool", action="store_true", help="PATH의 avbtool info_image도 실행")
    args = ap.parse_args()

    for p in (args.image_a, args.image_b):
        if not p.is_file():
            ap.error(f"파일을 찾을 수 없습니다: {p}")

    try:
        raw_a = args.image_a.read_bytes()
        raw_b = args.image_b.read_bytes()
        info_a = dissect(args.image_a)
        info_b = dissect(args.image_b)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    comparison = compare_infos(info_a, info_b, raw_a, raw_b)
    if args.run_avbtool:
        info_a["avbtool_info_image"] = run_avbtool(args.image_a)
        info_b["avbtool_info_image"] = run_avbtool(args.image_b)

    print_info("A", info_a)
    print_info("B", info_b)
    print_compare(comparison)

    if args.run_avbtool:
        print("\n[avbtool: A]")
        print(info_a.get("avbtool_info_image") or "avbtool 없음")
        print("\n[avbtool: B]")
        print(info_b.get("avbtool_info_image") or "avbtool 없음")

    if args.extract:
        args.extract.mkdir(parents=True, exist_ok=True)
        extract_regions(info_a, raw_a, args.extract, "A")
        extract_regions(info_b, raw_b, args.extract, "B")
        print(f"\n추출 완료: {args.extract}")

    report = {"A": info_a, "B": info_b, "comparison": comparison}
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON 저장: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
