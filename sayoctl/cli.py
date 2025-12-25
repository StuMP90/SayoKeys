from __future__ import annotations

import os
import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .protocol import (
    SAYO_VID,
    SayoDevice,
    enumerate_sayo_devices,
    parse_hex_bytes,
)


app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

keys_app = typer.Typer(add_completion=False, no_args_is_help=True)
macros_app = typer.Typer(add_completion=False, no_args_is_help=True)
strings_app = typer.Typer(add_completion=False, no_args_is_help=True)
probe_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(keys_app, name="keys")
app.add_typer(macros_app, name="macros")
app.add_typer(strings_app, name="strings")
app.add_typer(probe_app, name="probe")


def _pick_device(path: Optional[str]) -> str:
    if path:
        return path

    devs = enumerate_sayo_devices()
    if not devs:
        raise typer.BadParameter(
            "No Sayo devices found. If you are on Linux, you may need udev permissions for VID 0x8089."
        )
    if len(devs) > 1:
        console.print("Multiple devices found; pass --path to select one.")
        for d in devs:
            console.print(f"- {d.path} (pid=0x{d.product_id:04x})")
        raise typer.Exit(code=2)
    return devs[0].path


@app.command("list")
def list_devices(vid: int = SAYO_VID, pid: int = 0, json_out: bool = False):
    """List connected Sayobot devices (VID 0x8089)."""
    devs = enumerate_sayo_devices(vid=vid, pid=pid)
    if json_out:
        console.print(
            json.dumps([d.__dict__ for d in devs], ensure_ascii=False, indent=2)
        )
        return

    t = Table(title="Sayo devices")
    t.add_column("path")
    t.add_column("vid")
    t.add_column("pid")
    t.add_column("manufacturer")
    t.add_column("product")
    t.add_column("iface")
    for d in devs:
        t.add_row(
            d.path,
            f"0x{d.vendor_id:04x}",
            f"0x{d.product_id:04x}",
            d.manufacturer_string or "",
            d.product_string or "",
            "" if d.interface_number is None else str(d.interface_number),
        )
    console.print(t)


@app.command("dev-id")
def dev_id(path: Optional[str] = typer.Option(None, help="hid path from `list`")):
    """Read the device id pair (cmd 0xFE)."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        a, b = dev.get_dev_id()
    console.print({"id0": a, "id1": b})


@app.command("dev-name")
def dev_name(path: Optional[str] = typer.Option(None, help="hid path from `list`")):
    """Read the device name (cmd 0x08)."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        name = dev.get_dev_name()
    console.print(name)


@app.command("set-dev-name")
def set_dev_name(
    name: str,
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Set the device name (cmd 0x08)."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        dev.set_dev_name(name)
    console.print("ok")


@app.command("raw")
def raw(
    cmd: str = typer.Argument(..., help="Command byte, e.g. 0xFE"),
    data: list[str] = typer.Argument(None, help="Data bytes as hex, e.g. 01 ff 0a"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Send an arbitrary command and print the 64-byte response."""
    p = _pick_device(path)
    cmd_i = int(cmd, 16)
    payload = parse_hex_bytes(data or [])
    with SayoDevice(p) as dev:
        resp = dev.exchange(cmd_i, payload)

    console.print(
        {
            "id": resp.raw[0],
            "cmd": resp.raw[1],
            "data_len": resp.raw[2],
            "data": [b for b in resp.data],
            "raw": [b for b in resp.raw],
        }
    )


@keys_app.command("dump")
def keys_dump(
    out: Optional[str] = typer.Option(None, help="Write JSON to file (default: print)"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Dump current key mappings (cmd 0x06) as JSON."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        data = dev.list_keys()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        console.print_json(json.dumps(data, ensure_ascii=False))


@keys_app.command("set")
def keys_set(
    number: int = typer.Argument(..., help="Key/button number"),
    key_type: int = typer.Argument(..., help="Type byte"),
    v0: int = typer.Argument(...),
    v1: int = typer.Argument(...),
    v2: int = typer.Argument(...),
    v3: int = typer.Argument(...),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Set a single key mapping (cmd 0x06 write)."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        res = dev.set_key(number=number, key_type=key_type, values=[v0, v1, v2, v3])
    console.print(res)


@macros_app.command("names")
def macros_names(
    out: Optional[str] = typer.Option(None, help="Write JSON to file (default: print)"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """List macro/script slot names (cmd 0xF1)."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        data = dev.list_macro_names()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        console.print_json(json.dumps(data, ensure_ascii=False))


@macros_app.command("set-name")
def macros_set_name(
    number: int = typer.Argument(..., help="Macro slot number"),
    name: str = typer.Argument(..., help="Name (max 32 bytes utf-8; will be truncated)"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Set macro/script slot name (cmd 0xF1 write)."""
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        dev.set_macro_name(number=number, name=name)
    console.print("ok")


@macros_app.command("dump-script")
def macros_dump_script(
    out: Optional[str] = typer.Argument(None, help="Output file (binary)"),
    out_opt: Optional[str] = typer.Option(None, "--out", help="Output file (binary)"),
    max_len: int = typer.Option(8192, help="Max bytes to read"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Dump raw macro/script bytecode (cmd 0xF0 read) to a file."""
    out_path = out_opt or out or "script.bin"
    p = _pick_device(path)
    with SayoDevice(p) as dev:
        blob = dev.read_script(max_len=max_len)
    with open(out_path, "wb") as f:
        f.write(blob)
    # If running via sudo, avoid leaving root-owned files in the project directory.
    if os.geteuid() == 0:
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid:
            try:
                os.chown(out_path, int(sudo_uid), int(sudo_gid))
            except Exception:
                pass
    console.print({"bytes": len(blob), "out": out_path})


@macros_app.command("write-script")
def macros_write_script(
    inp: str = typer.Argument(..., help="Input file (binary)"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Write raw macro/script bytecode (cmd 0xF0 write) from a file."""
    p = _pick_device(path)
    with open(inp, "rb") as f:
        blob = f.read()
    with SayoDevice(p) as dev:
        dev.write_script(blob)
    console.print({"bytes": len(blob), "status": "ok"})


@strings_app.command("list")
def strings_list(
    out: Optional[str] = typer.Option(None, help="Write JSON to file (default: print)"),
    limit: int = typer.Option(64, help="Max number of slots to query"),
    uk: bool = typer.Option(False, "--uk", help="Apply UK layout symbol swap when displaying"),
    translate: str = typer.Option(
        "none",
        help="Translate symbols for display: none, us-to-uk, uk-to-us",
    ),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """List programmable string slots (cmd 0x0C)."""
    p = _pick_device(path)
    if translate == "none" and uk:
        translate = "uk-to-us"
    table = _pick_translation(translate)
    with SayoDevice(p) as dev:
        data = dev.list_strings(limit=limit)

    if table:
        for item in data:
            if isinstance(item.get("text"), str):
                item["text"] = _translate_symbols(item["text"], table)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        console.print_json(json.dumps(data, ensure_ascii=False))


@strings_app.command("get")
def strings_get(
    number: int = typer.Argument(..., help="String slot number"),
    uk: bool = typer.Option(False, "--uk", help="Apply UK layout symbol swap when displaying"),
    translate: str = typer.Option(
        "none",
        help="Translate symbols for display: none, us-to-uk, uk-to-us",
    ),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Get one programmable string slot (cmd 0x0C)."""
    p = _pick_device(path)
    if translate == "none" and uk:
        translate = "uk-to-us"
    table = _pick_translation(translate)
    with SayoDevice(p) as dev:
        data = dev.get_string(number)
    if table and isinstance(data.get("text"), str):
        data["text"] = _translate_symbols(data["text"], table)
    console.print(data)


@strings_app.command("set")
def strings_set(
    number: int = typer.Argument(..., help="String slot number"),
    text: str = typer.Argument(..., help="Text to send (stored as GBK/CP936 like upstream)"),
    uk: bool = typer.Option(False, "--uk", help="Apply UK layout symbol swap before storing"),
    translate: str = typer.Option(
        "none",
        help="Translate symbols before storing: none, us-to-uk, uk-to-us",
    ),
    mode: int = typer.Option(0, help="Mode byte (usually 0)"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Set one programmable string slot (cmd 0x0C write)."""
    p = _pick_device(path)
    if translate == "none" and uk:
        translate = "uk-to-us"
    table = _pick_translation(translate)
    if table:
        text = _translate_symbols(text, table)
    with SayoDevice(p) as dev:
        dev.set_string(number=number, text=text, mode=mode)
    console.print("ok")


def _extract_ascii_runs(buf: bytes, *, min_len: int = 6) -> list[str]:
    runs: list[str] = []
    cur = bytearray()
    for b in buf:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        runs.append(cur.decode("ascii", errors="ignore"))
    return runs


@probe_app.command("ascii")
def probe_ascii(
    start: int = typer.Option(0, help="Start cmd (decimal)"),
    end: int = typer.Option(255, help="End cmd (decimal, inclusive)"),
    payload: list[str] = typer.Option(None, help="Payload bytes as hex, e.g. --payload 00 --payload 00"),
    min_len: int = typer.Option(8, help="Minimum ASCII run length"),
    timeout_ms: int = typer.Option(200, help="Read timeout per command"),
    path: Optional[str] = typer.Option(None, help="hid path from `list`"),
):
    """Scan command codes and print any printable ASCII found in responses."""
    p = _pick_device(path)
    data = parse_hex_bytes(payload or [])
    matches: list[dict[str, object]] = []

    with SayoDevice(p, read_timeout_ms=timeout_ms) as dev:
        for cmd in range(start, end + 1):
            try:
                resp = dev.exchange(cmd, data)
            except Exception:
                continue
            runs = _extract_ascii_runs(resp.raw, min_len=min_len)
            if runs:
                matches.append({"cmd": cmd, "ascii": runs})

    console.print_json(json.dumps(matches, ensure_ascii=False, indent=2))


_UK_US_SYMBOL_SWAP = {
    "#": "£",
    "£": "#",
    "@": '"',
    '"': "@",
}


def _translate_symbols(text: str, table: dict[str, str]) -> str:
    return "".join(table.get(ch, ch) for ch in text)


def _pick_translation(name: str) -> dict[str, str]:
    if name == "none":
        return {}
    if name == "us-to-uk":
        return _UK_US_SYMBOL_SWAP
    if name == "uk-to-us":
        return _UK_US_SYMBOL_SWAP
    raise typer.BadParameter("translate must be one of: none, us-to-uk, uk-to-us")
