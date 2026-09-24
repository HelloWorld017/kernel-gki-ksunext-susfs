import argparse
import hashlib
import io
import os
import re
import shutil
import struct
import sys
import urllib.request
import zipfile
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit

USER_AGENT = "nenw_kernel_fetcher/1.0"
IMAGES_URL = "https://developers.google.com/android/images"
TERMS_COOKIE = "devsite_wall_acks=nexus-image-tos"
DEFAULT_PREFETCH = 4 * 1024 * 1024
LOCAL_FILE_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_FILE_MAGIC = 0x04034B50


class RangeError(RuntimeError):
    pass


class FactoryImageRows(HTMLParser):
    """Collect download links from each release row on Google's images page."""

    def __init__(self):
        super().__init__()
        self.rows = {}
        self.row_id = None
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "tr":
            self.row_id = attrs.get("id")
            self.links = []
        elif tag == "a" and self.row_id and attrs.get("href"):
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "tr" and self.row_id:
            if self.row_id.lower() in self.rows:
                raise ValueError(f"duplicate factory image row: {self.row_id}")
            self.rows[self.row_id.lower()] = self.links
            self.row_id = None
            self.links = []


def find_factory_url(device: str, tag: str) -> str:
    if not re.fullmatch(r"[a-z0-9_-]+", device):
        raise ValueError("device must be a lowercase device codename")
    if not re.fullmatch(r"[A-Za-z0-9.]+", tag):
        raise ValueError("tag must contain only letters, digits and dots")

    request = urllib.request.Request(
        IMAGES_URL, headers={"Cookie": TERMS_COOKIE, "User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        page = response.read().decode("utf-8")
    parser = FactoryImageRows()
    parser.feed(page)

    row_id = (device + tag).lower()
    if row_id not in parser.rows:
        raise ValueError(f"no factory image listed for {device} / {tag}")

    filename = re.compile(
        rf"^{re.escape(device)}-{re.escape(tag.lower())}-factory-[0-9a-f]+\.zip$"
    )
    matches = [
        link
        for link in parser.rows[row_id]
        if urlsplit(link).scheme == "https"
        and urlsplit(link).netloc == "dl.google.com"
        and urlsplit(link).path.startswith("/dl/android/aosp/")
        and filename.fullmatch(PurePosixPath(urlsplit(link).path).name)
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one factory ZIP for {device} / {tag}; found {len(matches)}")
    return matches[0]


class HTTPRangeReader(io.RawIOBase):
    def __init__(self, url: str, prefetch: int = DEFAULT_PREFETCH):
        super().__init__()
        self.url = url
        self.prefetch = max(prefetch, 64 * 1024)
        self.pos = 0
        self.bytes_transferred = 0
        self.requests = 0
        self._cache_start = -1
        self._cache = b""
        self.size = self._probe_size()

    def _request(self, start: int, end: int) -> bytes:
        if start < 0 or end < start or end >= self.size:
            raise RangeError(f"invalid byte range {start}-{end} for size {self.size}")
        req = urllib.request.Request(
            self.url,
            headers={
                "Range": f"bytes={start}-{end}",
                "Accept-Encoding": "identity",
                "User-Agent": USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = getattr(resp, "status", resp.getcode())
            if status != 206:
                raise RangeError(
                    f"server ignored Range request: expected HTTP 206, got {status}"
                )
            data = resp.read()
            content_range = resp.headers.get("Content-Range", "")
            expected_prefix = f"bytes {start}-{end}/"
            if not content_range.startswith(expected_prefix):
                raise RangeError(f"unexpected Content-Range: {content_range!r}")
        expected = end - start + 1
        if len(data) != expected:
            raise RangeError(
                f"short ranged response: wanted {expected} bytes, got {len(data)}"
            )
        self.bytes_transferred += len(data)
        self.requests += 1
        return data

    def _probe_size(self) -> int:
        req = urllib.request.Request(
            self.url,
            headers={
                "Range": "bytes=0-0",
                "Accept-Encoding": "identity",
                "User-Agent": USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = getattr(resp, "status", resp.getcode())
            if status != 206:
                raise RangeError(
                    f"URL does not provide usable HTTP byte ranges (status {status})"
                )
            content_range = resp.headers.get("Content-Range", "")
            # Example: bytes 0-0/3456789
            try:
                total = int(content_range.rsplit("/", 1)[1])
            except Exception as exc:
                raise RangeError(
                    f"cannot determine remote size from Content-Range: {content_range!r}"
                ) from exc
            # Consume the one requested byte so the response is complete.
            body = resp.read()
            if len(body) != 1:
                raise RangeError("range probe did not return exactly one byte")
        self.bytes_transferred += 1
        self.requests += 1
        return total

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self.pos + offset
        elif whence == io.SEEK_END:
            new_pos = self.size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if new_pos < 0:
            raise ValueError("negative seek position")
        self.pos = new_pos
        return self.pos

    def read(self, size: int = -1) -> bytes:
        if self.pos >= self.size:
            return b""
        if size is None or size < 0:
            size = self.size - self.pos
        size = min(size, self.size - self.pos)
        if size == 0:
            return b""

        start = self.pos
        end = start + size
        cache_end = self._cache_start + len(self._cache)
        if self._cache_start <= start and end <= cache_end:
            off = start - self._cache_start
            out = self._cache[off : off + size]
            self.pos += len(out)
            return out

        fetch_len = max(size, self.prefetch)
        fetch_end = min(self.size, start + fetch_len)
        data = self._request(start, fetch_end - 1)
        self._cache_start = start
        self._cache = data
        out = data[:size]
        self.pos += len(out)
        return out


class SubRangeReader(io.RawIOBase):
    """Seekable view into a byte range of another seekable reader."""

    def __init__(self, base: HTTPRangeReader, start: int, size: int):
        super().__init__()
        self.base = base
        self.start = start
        self.size = size
        self.pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self.pos + offset
        elif whence == io.SEEK_END:
            new_pos = self.size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if new_pos < 0:
            raise ValueError("negative seek position")
        self.pos = new_pos
        return self.pos

    def read(self, size: int = -1) -> bytes:
        if self.pos >= self.size:
            return b""
        if size is None or size < 0:
            size = self.size - self.pos
        size = min(size, self.size - self.pos)
        self.base.seek(self.start + self.pos)
        data = self.base.read(size)
        self.pos += len(data)
        return data


def raw_member_data_offset(reader: HTTPRangeReader, info: zipfile.ZipInfo) -> int:
    reader.seek(info.header_offset)
    hdr = reader.read(LOCAL_FILE_HEADER.size)
    if len(hdr) != LOCAL_FILE_HEADER.size:
        raise RangeError("truncated local ZIP header")
    (
        magic,
        _ver,
        _flags,
        _method,
        _mtime,
        _mdate,
        _crc,
        _csize,
        _usize,
        name_len,
        extra_len,
    ) = LOCAL_FILE_HEADER.unpack(hdr)
    if magic != LOCAL_FILE_MAGIC:
        raise RangeError(f"bad local ZIP header magic at {info.header_offset}")
    return info.header_offset + LOCAL_FILE_HEADER.size + name_len + extra_len


def find_inner_image_zip(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    candidates = []
    for info in zf.infolist():
        name = PurePosixPath(info.filename).name
        if name.startswith("image-") and name.endswith(".zip"):
            candidates.append(info)
    if not candidates:
        raise RangeError("factory ZIP has no image-<device>-<build>.zip member")
    # A factory package normally has one. Largest is the safest choice if not.
    return max(candidates, key=lambda x: x.file_size)


def find_boot_img(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    matches = [
        info
        for info in zf.infolist()
        if PurePosixPath(info.filename).name == "boot.img" and not info.is_dir()
    ]
    if not matches:
        raise RangeError("inner image ZIP has no boot.img member")
    if len(matches) > 1:
        matches.sort(key=lambda x: len(PurePosixPath(x.filename).parts))
    return matches[0]


def extract_boot_by_range(url: str, output: str, prefetch: int) -> dict:
    remote = HTTPRangeReader(url, prefetch=prefetch)
    with zipfile.ZipFile(remote) as outer:
        inner_info = find_inner_image_zip(outer)
        if inner_info.compress_type != zipfile.ZIP_STORED:
            raise RangeError(
                "inner image-*.zip is compressed in the outer factory ZIP; "
                "efficient nested Range extraction is not possible without a full decode"
            )
        inner_start = raw_member_data_offset(remote, inner_info)
        inner_reader = SubRangeReader(remote, inner_start, inner_info.compress_size)
        with zipfile.ZipFile(inner_reader) as inner:
            boot_info = find_boot_img(inner)
            os.makedirs(os.path.dirname(os.path.abspath(output)) or ".", exist_ok=True)
            with inner.open(boot_info, "r") as src, open(output, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)

    return {
        "remote_size": remote.size,
        "bytes_transferred": remote.bytes_transferred,
        "requests": remote.requests,
        "inner_name": inner_info.filename,
        "inner_method": inner_info.compress_type,
        "boot_name": boot_info.filename,
        "boot_compressed_size": boot_info.compress_size,
        "boot_size": boot_info.file_size,
        "boot_crc32": f"{boot_info.CRC:08x}",
    }


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("device", help="Pixel device codename, e.g. husky")
    ap.add_argument("tag", help="exact factory build tag, e.g. CP1A.260505.005")
    ap.add_argument("--output", default="stock-boot.img", help="extracted stock boot.img")
    ap.add_argument(
        "--prefetch-mib",
        type=int,
        default=4,
        help="Range read-ahead size in MiB (default: 4)",
    )
    args = ap.parse_args()

    try:
        url = find_factory_url(args.device, args.tag)
        print(f"Factory ZIP URL: {url}")
        stats = extract_boot_by_range(
            url, args.output, max(args.prefetch_mib, 1) * 1024 * 1024
        )
    except Exception as exc:
        print(f"ERROR: factory boot extraction failed: {exc}", file=sys.stderr)
        return 2

    print(f"Factory ZIP: {stats['remote_size']:,} bytes")
    print(f"Inner ZIP:    {stats['inner_name']} (STORE)")
    print(
        f"boot.img:     {stats['boot_size']:,} bytes "
        f"(compressed {stats['boot_compressed_size']:,}, CRC32 {stats['boot_crc32']})"
    )
    print(
        f"HTTP fetched: {stats['bytes_transferred']:,} bytes "
        f"in {stats['requests']} ranged requests "
        f"({stats['bytes_transferred'] / stats['remote_size']:.2%} of factory ZIP)"
    )
    print(f"stock SHA256: {sha256_file(args.output)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
