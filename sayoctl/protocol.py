from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional

try:
    import hid
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "Failed to import the 'hid' package because the hidapi system library is missing. "
        "On Debian/Ubuntu try: sudo apt-get install libhidapi-hidraw0 libhidapi-libusb0. "
        "On Fedora: sudo dnf install hidapi."
    ) from e


SAYO_VID = 0x8089


class SayoProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class SayoDeviceInfo:
    path: str
    vendor_id: int
    product_id: int
    manufacturer_string: str | None = None
    product_string: str | None = None
    serial_number: str | None = None
    interface_number: int | None = None


def enumerate_sayo_devices(vid: int = SAYO_VID, pid: int = 0) -> list[SayoDeviceInfo]:
    devices: list[SayoDeviceInfo] = []
    for d in hid.enumerate(vid, pid):
        # Sayo_CLI filters usage_page > 0xFF and usage == 1.
        # Not all backends expose these fields, so treat them as optional.
        usage_page = d.get("usage_page")
        usage = d.get("usage")
        if usage_page is not None and usage is not None:
            if not (usage_page > 0xFF and usage == 1):
                continue

        path = d.get("path")
        if path is None:
            continue

        if isinstance(path, bytes):
            path_str = path.decode(errors="ignore")
        else:
            path_str = str(path)

        devices.append(
            SayoDeviceInfo(
                path=path_str,
                vendor_id=int(d.get("vendor_id") or 0),
                product_id=int(d.get("product_id") or 0),
                manufacturer_string=d.get("manufacturer_string"),
                product_string=d.get("product_string"),
                serial_number=d.get("serial_number"),
                interface_number=d.get("interface_number"),
            )
        )
    return devices


def _checksum(payload: bytes) -> int:
    return sum(payload) & 0xFF


def build_report(cmd: int, data: bytes = b"", report_id: int = 0x02) -> bytes:
    if len(data) > 60:
        raise ValueError("data too long (max 60 bytes)")

    data_len = len(data)
    # Layout: [id][cmd][data_len][data...][checksum][padding...]
    buf = bytearray(64)
    buf[0] = report_id & 0xFF
    buf[1] = cmd & 0xFF
    buf[2] = data_len & 0xFF
    buf[3 : 3 + data_len] = data

    chk_index = 3 + data_len
    buf[chk_index] = _checksum(buf[0:chk_index])
    return bytes(buf)


@dataclass
class SayoResponse:
    raw: bytes

    @property
    def cmd(self) -> int:
        return self.raw[1]

    @property
    def data_len(self) -> int:
        return self.raw[2]

    @property
    def data(self) -> bytes:
        return self.raw[3 : 3 + self.data_len]


class SayoDevice:
    def __init__(self, path: str, *, read_timeout_ms: int = 2000):
        self._path = path
        self._timeout = read_timeout_ms
        self._dev: hid.Device | None = None
        self._strings_backend: int | None = None
        self._nonblocking: bool = False

    def open(self) -> None:
        if self._dev is not None:
            return
        # The Python package `hid` exposes `hid.Device`, not `hid.device()`.
        # `path` must be bytes for some backends.
        path: bytes
        if isinstance(self._path, bytes):
            path = self._path
        else:
            path = self._path.encode()
        try:
            dev = hid.Device(path=path)
        except Exception as e:  # pragma: no cover
            raise SayoProtocolError(
                "Unable to open HID device. On Linux this is usually a permissions/udev issue. "
                "Try running as root once to confirm (sudo sayoctl ...), or add a udev rule "
                "for VID 0x8089 and your PID (e.g. 0x0008) to grant access to /dev/hidraw*."
            ) from e
        self._dev = dev

        # Some hidapi backends may ignore the timeout parameter to read().
        # Prefer non-blocking reads (if supported) and implement our own timeout.
        set_nonblocking = getattr(dev, "set_nonblocking", None)
        if callable(set_nonblocking):
            try:
                set_nonblocking(True)
                self._nonblocking = True
            except Exception:
                self._nonblocking = False

    def close(self) -> None:
        if self._dev is not None:
            try:
                self._dev.close()
            finally:
                self._dev = None
                self._nonblocking = False

    def __enter__(self) -> "SayoDevice":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def exchange(self, cmd: int, data: bytes = b"", *, report_id: int = 0x02) -> SayoResponse:
        if self._dev is None:
            raise RuntimeError("device not open")

        report = build_report(cmd=cmd, data=data, report_id=report_id)
        written = self._dev.write(report)
        if written <= 0:
            raise SayoProtocolError("hid write failed")

        if self._nonblocking:
            deadline = time.monotonic() + (self._timeout / 1000.0)
            data_out: list[int] = []
            while time.monotonic() < deadline:
                chunk = self._dev.read(64)
                if chunk:
                    data_out = chunk
                    break
                time.sleep(0.01)
            raw = bytes(data_out)
        else:
            raw = bytes(self._dev.read(64, timeout=self._timeout))

        if len(raw) != 64:
            raise SayoProtocolError(f"hid read failed/timeout (got {len(raw)} bytes)")
        return SayoResponse(raw=raw)

    # Concrete commands confirmed from Sayo_CLI
    def get_dev_id(self) -> tuple[int, int]:
        resp = self.exchange(0xFE, b"")
        if resp.cmd != 0:
            raise SayoProtocolError(f"device returned error cmd={resp.cmd}")
        if len(resp.data) < 4:
            raise SayoProtocolError("dev-id response too short")
        a = resp.data[0] | (resp.data[1] << 8)
        b = resp.data[2] | (resp.data[3] << 8)
        return a, b

    def get_dev_name(self) -> str:
        # Sayo_CLI sends cmd 0x08 with data_len 1 and a zero byte.
        resp = self.exchange(0x08, b"\x00")
        if resp.cmd != 0:
            raise SayoProtocolError(f"device returned error cmd={resp.cmd}")

        data = resp.data
        # Heuristic decoding: firmware seems to return UTF-16LE (wchar_t*) in Sayo_CLI.
        # Try UTF-16LE first, fall back to UTF-8.
        try:
            # Trim trailing NULs.
            trimmed = data
            while trimmed.endswith(b"\x00\x00"):
                trimmed = trimmed[:-2]
            s = trimmed.decode("utf-16le", errors="strict")
            return s
        except Exception:
            return data.rstrip(b"\x00").decode("utf-8", errors="replace")

    def set_dev_name(self, name: str) -> None:
        # Write path in Sayo_CLI uses UTF-16LE wchar_t buffer.
        encoded = (name + "\x00").encode("utf-16le")
        # cmd 0x08 expects data_len up to 60. Keep it safe.
        if len(encoded) > 60:
            raise ValueError("name too long")
        resp = self.exchange(0x08, encoded)
        if resp.cmd != 0:
            raise SayoProtocolError(f"device returned error cmd={resp.cmd}")

    # Key mappings (Sayo_CLI: O2Protocol::Buttons cmd=6)
    def list_keys(self, *, limit: int = 8) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        key_number = 0
        while key_number < limit:
            # data_len=2, payload = [pattern=0, number]
            resp = self.exchange(0x06, bytes([0x00, key_number & 0xFF]))
            if resp.cmd != 0:
                break
            data = resp.data
            if len(data) < 6:
                raise SayoProtocolError("key response too short")
            # Response layout from struct key:
            # [pattern][number][type][retain_1][plain0][plain1][plain2][plain3]...
            entry = {
                "number": data[1],
                "type": data[2],
                "values": [data[4], data[5], data[6], data[7]] if len(data) >= 8 else [],
            }
            out.append(entry)
            key_number += 1
        return out

    def set_key(self, number: int, key_type: int, values: Iterable[int]) -> dict[str, object]:
        vals = list(values)
        if len(vals) != 4:
            raise ValueError("values must be 4 bytes")
        payload = bytes(
            [
                0x01,  # pattern=1 (write)
                number & 0xFF,
                key_type & 0xFF,
                0x00,  # retain
                vals[0] & 0xFF,
                vals[1] & 0xFF,
                vals[2] & 0xFF,
                vals[3] & 0xFF,
            ]
        )
        resp = self.exchange(0x06, payload)
        if resp.cmd != 0:
            raise SayoProtocolError(f"device returned error cmd={resp.cmd}")
        data = resp.data
        if len(data) < 8:
            raise SayoProtocolError("key write response too short")
        return {"number": data[1], "type": data[2], "values": [data[4], data[5], data[6], data[7]]}

    # Macros/scripts
    # - Script bytes: cmd 0xF0
    #   Read: data_len=2, payload=[addr_h, addr_l]
    #   Write: data_len=2+N, payload=[addr_h, addr_l] + N bytes, where N<=54
    # - Script slot names: cmd 0xF1
    #   Read: data_len=2, payload=[pattern=0, number]
    #   Write: data_len=34, payload=[pattern=1, number] + 32 bytes name

    def read_script(self, *, max_len: int = 8192) -> bytes:
        buf = bytearray()
        addr = 0
        while addr < max_len:
            resp = self.exchange(0xF0, bytes([(addr >> 8) & 0xFF, addr & 0xFF]))
            if resp.cmd != 0:
                break
            chunk = resp.data
            if not chunk:
                break
            buf.extend(chunk)
            addr += len(chunk)
            # Heuristic stop: upstream null-terminates and expects a terminating marker.
            if buf.endswith(b"\x00") and addr > 1:
                # Don't over-aggressively stop; this just avoids runaway reads on some firmwares.
                pass
        return bytes(buf[:max_len])

    def write_script(self, data: bytes) -> None:
        if len(data) > 8192:
            raise ValueError("script too large (max 8192 bytes)")

        addr = 0
        while addr < len(data):
            chunk = data[addr : addr + 54]
            payload = bytes([(addr >> 8) & 0xFF, addr & 0xFF]) + chunk
            resp = self.exchange(0xF0, payload)
            if resp.cmd != 0:
                raise SayoProtocolError(f"script write failed cmd={resp.cmd} at addr={addr}")
            addr += len(chunk)

    def list_macro_names(self) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        number = 0
        while True:
            resp = self.exchange(0xF1, bytes([0x00, number & 0xFF]), report_id=0x02)
            if resp.cmd != 0:
                break
            data = resp.data
            if len(data) < 34:
                # pattern + number + 32 bytes name
                raise SayoProtocolError("macro name response too short")
            name_raw = data[2:34]
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            out.append({"number": data[1], "name": name})
            number += 1
        return out

    def set_macro_name(self, number: int, name: str) -> None:
        name_bytes = name.encode("utf-8", errors="replace")[:32]
        name_bytes = name_bytes.ljust(32, b"\x00")
        payload = bytes([0x01, number & 0xFF]) + name_bytes
        resp = self.exchange(0xF1, payload)
        if resp.cmd != 0:
            raise SayoProtocolError(f"macro-name write failed cmd={resp.cmd}")

    def _detect_strings_backend(self) -> int:
        if self._strings_backend is not None:
            return self._strings_backend

        # Some firmwares expose typed strings via cmd 0x0B (Ok_pwd-like), others via cmd 0x0C.
        try:
            r0b = self.exchange(0x0B, bytes([0x00, 0x00]))
            if r0b.cmd == 0 and r0b.data_len >= 4:
                s = r0b.data[2 : 2 + (r0b.data_len - 2)].split(b"\x00", 1)[0]
                if any(32 <= b <= 126 for b in s):
                    self._strings_backend = 0x0B
                    return self._strings_backend
        except Exception:
            pass

        self._strings_backend = 0x0C
        return self._strings_backend

    @staticmethod
    def _decode_0b_text(data: bytes) -> str:
        # Layout: [pattern][number][pwd...]
        if len(data) < 2:
            return ""
        raw = data[2:].split(b"\x00", 1)[0]
        # Some firmwares appear to return a fixed-length buffer with a non-NUL
        # terminator (e.g. 0x7f). Trim trailing non-printable bytes.
        raw = raw.rstrip(bytes([0x7F]))
        while raw and not (32 <= raw[-1] <= 126):
            raw = raw[:-1]
        return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _encode_0b_text(text: str) -> bytes:
        raw = text.encode("utf-8", errors="replace")
        # cmd 0x0B payload is: [pattern][number] + text + NUL
        # Total report data must be <= 60 bytes, so text must be <= 57 bytes.
        if len(raw) > 57:
            raw = raw[:57]
        return raw + b"\x00"

    @staticmethod
    def _decode_string_gbk_pairs(raw56: bytes) -> str:
        if len(raw56) != 56:
            raise ValueError("expected 56 bytes")
        out = bytearray()
        for i in range(0, 56, 2):
            hi = raw56[i]
            lo = raw56[i + 1]
            if hi == 0 and lo == 0:
                continue
            if hi == 0:
                out.append(lo)
            else:
                out.append(lo)
                out.append(hi)
        try:
            return out.decode("gbk", errors="strict")
        except Exception:
            return out.decode("latin-1", errors="replace")

    @staticmethod
    def _encode_string_gbk_pairs(text: str) -> bytes:
        try:
            raw = text.encode("gbk")
        except Exception:
            # Best-effort fallback; may not round-trip for non-ascii.
            raw = text.encode("latin-1", errors="replace")

        buf = bytearray(56)
        gbk_i = 0
        for data_i in range(0, 56, 2):
            if gbk_i >= len(raw):
                buf[data_i] = 0
                buf[data_i + 1] = 0
                continue

            b0 = raw[gbk_i]
            if b0 < 0x80:
                buf[data_i] = 0
                buf[data_i + 1] = b0
                gbk_i += 1
            else:
                if gbk_i + 1 >= len(raw):
                    # Truncated multibyte; stop.
                    buf[data_i] = 0
                    buf[data_i + 1] = 0
                    break
                b1 = raw[gbk_i + 1]
                # Store swapped: [b1, b0]
                buf[data_i] = b1
                buf[data_i + 1] = b0
                gbk_i += 2
        return bytes(buf)

    def list_strings(self, *, limit: int = 64) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        backend = self._detect_strings_backend()
        for number in range(limit):
            if backend == 0x0B:
                resp = self.exchange(0x0B, bytes([0x00, number & 0xFF]))
                if resp.cmd != 0:
                    break
                out.append({"number": resp.data[1] if resp.data_len >= 2 else number, "mode": 0, "text": self._decode_0b_text(resp.data)})
            else:
                resp = self.exchange(0x0C, bytes([0x00, number & 0xFF]))
                if resp.cmd != 0:
                    break
                data = resp.data
                if len(data) < 3 + 56:
                    raise SayoProtocolError("string response too short")
                mode = data[2]
                raw56 = data[3 : 3 + 56]
                text = self._decode_string_gbk_pairs(raw56)
                out.append({"number": data[1], "mode": mode, "text": text})
        return out

    def get_string(self, number: int) -> dict[str, object]:
        backend = self._detect_strings_backend()
        if backend == 0x0B:
            resp = self.exchange(0x0B, bytes([0x00, number & 0xFF]))
            if resp.cmd != 0:
                raise SayoProtocolError(f"device returned error cmd={resp.cmd}")
            return {"number": resp.data[1] if resp.data_len >= 2 else number, "mode": 0, "text": self._decode_0b_text(resp.data)}

        resp = self.exchange(0x0C, bytes([0x00, number & 0xFF]))
        if resp.cmd != 0:
            raise SayoProtocolError(f"device returned error cmd={resp.cmd}")
        data = resp.data
        if len(data) < 3 + 56:
            raise SayoProtocolError("string response too short")
        mode = data[2]
        raw56 = data[3 : 3 + 56]
        return {"number": data[1], "mode": mode, "text": self._decode_string_gbk_pairs(raw56)}

    def set_string(self, number: int, text: str, *, mode: int = 0) -> None:
        backend = self._detect_strings_backend()
        if backend == 0x0B:
            raw = self._encode_0b_text(text)
            payload = bytes([0x01, number & 0xFF]) + raw
            resp = self.exchange(0x0B, payload)
            if resp.cmd != 0:
                raise SayoProtocolError(f"string write failed cmd={resp.cmd}")
            return

        raw56 = self._encode_string_gbk_pairs(text)
        payload = bytes([0x01, number & 0xFF, mode & 0xFF]) + raw56
        resp = self.exchange(0x0C, payload)
        if resp.cmd != 0:
            raise SayoProtocolError(f"string write failed cmd={resp.cmd}")


def parse_hex_bytes(items: Iterable[str]) -> bytes:
    out = bytearray()
    for it in items:
        it = it.strip().lower()
        if it.startswith("0x"):
            it = it[2:]
        if it == "":
            continue
        out.append(int(it, 16) & 0xFF)
    return bytes(out)
