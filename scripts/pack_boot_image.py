import argparse
import hashlib
import os
import struct
import sys

PAGE_SIZE_V3_V4 = 4096


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ceil_page(n: int, page: int = PAGE_SIZE_V3_V4) -> int:
    return (n + page - 1) // page * page


def repack_boot_v3_v4(stock_boot: str, kernel_image: str, output: str) -> dict:
    with open(stock_boot, "rb") as f:
        stock = f.read()
    with open(kernel_image, "rb") as f:
        kernel = f.read()

    if len(stock) < PAGE_SIZE_V3_V4 or stock[:8] != b"ANDROID!":
        raise ValueError("stock boot.img is not a valid Android boot image")

    kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from("<4I", stock, 8)
    header_version = struct.unpack_from("<I", stock, 40)[0]
    if header_version not in (3, 4):
        raise ValueError(
            f"this repacker intentionally supports only boot header v3/v4; got v{header_version}"
        )
    if header_size > PAGE_SIZE_V3_V4:
        raise ValueError(f"unexpected boot header size {header_size}")

    old_kernel_off = PAGE_SIZE_V3_V4
    old_ramdisk_off = old_kernel_off + ceil_page(kernel_size)
    old_ramdisk_end = old_ramdisk_off + ramdisk_size
    if old_ramdisk_end > len(stock):
        raise ValueError("stock boot.img is truncated")
    ramdisk = stock[old_ramdisk_off:old_ramdisk_end]

    header_page = bytearray(stock[:PAGE_SIZE_V3_V4])
    struct.pack_into("<I", header_page, 8, len(kernel))

    old_signature_size = 0
    if header_version == 4:
        old_signature_size = struct.unpack_from("<I", stock, 1580)[0]
        # The GKI boot signature authenticates the original kernel/ramdisk and
        # cannot remain valid after replacing the kernel. It is not the OEM AVB
        # chain used for the device-specific verified boot decision.
        struct.pack_into("<I", header_page, 1580, 0)

    with open(output, "wb") as out:
        out.write(header_page)
        out.write(kernel)
        out.write(b"\0" * (ceil_page(len(kernel)) - len(kernel)))
        out.write(ramdisk)
        out.write(b"\0" * (ceil_page(len(ramdisk)) - len(ramdisk)))

    result_size = os.path.getsize(output)
    return {
        "header_version": header_version,
        "header_size": header_size,
        "os_version_raw": os_version,
        "stock_kernel_size": kernel_size,
        "new_kernel_size": len(kernel),
        "ramdisk_size": ramdisk_size,
        "removed_boot_signature_size": old_signature_size,
        "stock_boot_size": len(stock),
        "output_boot_size": result_size,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stock", required=True, help="stock boot.img")
    ap.add_argument("--kernel", required=True, help="replacement uncompressed GKI Image")
    ap.add_argument("--output", default="boot.img", help="repacked boot output")
    args = ap.parse_args()

    try:
        repack = repack_boot_v3_v4(args.stock, args.kernel, args.output)
    except Exception as exc:
        print(f"ERROR: boot repack failed: {exc}", file=sys.stderr)
        return 3
    print(
        "Repacked:     "
        f"header v{repack['header_version']}, "
        f"kernel {repack['stock_kernel_size']:,} -> {repack['new_kernel_size']:,} bytes, "
        f"ramdisk {repack['ramdisk_size']:,} bytes, "
        f"removed GKI signature {repack['removed_boot_signature_size']:,} bytes"
    )
    print(f"output SHA256: {sha256_file(args.output)}")
    if repack["output_boot_size"] > repack["stock_boot_size"]:
        print(
            "WARNING: repacked boot image is larger than the stock boot image; "
            "check the device boot partition size before flashing.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
