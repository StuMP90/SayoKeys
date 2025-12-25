# sayoctl

CLI to manage settings on Sayobot Sayo keyboards over USB HID.

## Install

### Python

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Linux dependencies

The `hid` Python package requires the native `hidapi` shared library.

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install libhidapi-hidraw0 libhidapi-libusb0
```

Fedora:

```bash
sudo dnf install hidapi
```

### Linux permissions (udev)

On Linux you may need udev rules similar to upstream `Sayo_CLI`.

Common Sayo VID/PIDs:

- VID `0x8089`
- PID `0x0002`, `0x0003`, `0x0004`, `0x0005`, `0x0008` (varies by model)

Example udev rule (adjust PID if needed):

```bash
sudo tee /etc/udev/rules.d/98-sayo.rules >/dev/null <<'EOF'
KERNEL=="hidraw*", ATTRS{idVendor}=="8089", ATTRS{idProduct}=="0008", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Usage

```bash
sudo -E .venv/bin/sayoctl list

# GUI (PySide6)
.venv/bin/sayogui

# If you must run under sudo (not recommended for Qt GUIs), you may need to disable
# Qt's platform theme integration to avoid DBus-related crashes:
sudo -E env QT_QPA_PLATFORMTHEME= .venv/bin/sayogui

# Device information
sudo -E .venv/bin/sayoctl dev-id
sudo -E .venv/bin/sayoctl dev-name
sudo -E .venv/bin/sayoctl set-dev-name "My Sayo"

# Key mappings
sudo -E .venv/bin/sayoctl keys dump
sudo -E .venv/bin/sayoctl keys dump --out keys.json

# sayoctl keys set <number> <type> <v0> <v1> <v2> <v3>
sudo -E .venv/bin/sayoctl keys set 0 1 4 0 0 0

# Macros
sudo -E .venv/bin/sayoctl macros names
sudo -E .venv/bin/sayoctl macros names --out macro_names.json
sudo -E .venv/bin/sayoctl macros set-name 0 "Macro 0"

# Programmable strings
sudo -E .venv/bin/sayoctl strings list --limit 10 --uk
sudo -E .venv/bin/sayoctl strings get 0 --uk
sudo -E .venv/bin/sayoctl strings set 0 "hello@example.com" --uk

# If your host keyboard layout is UK, some symbols may be swapped when the device types strings
# (notably '@' <-> '"' and '#' <-> '£'). You can use --translate to compensate.
sudo -E .venv/bin/sayoctl strings get 0 --uk
sudo -E .venv/bin/sayoctl strings set 0 "hello@example.com" --uk

# Bind a physical key to a string slot (example: key index 7 -> string slot 7)
# This sets key mapping type=8 with values [slot, 0, 2, 0]
sudo -E .venv/bin/sayoctl keys set 7 8 7 0 2 0

# Macro script bytecode (advanced)
sudo -E .venv/bin/sayoctl macros dump-script
sudo -E .venv/bin/sayoctl macros dump-script --out script.bin
sudo -E .venv/bin/sayoctl macros write-script script.bin

# Send an arbitrary command (for exploring additional settings)
sudo -E .venv/bin/sayoctl raw 0xFE
sudo -E .venv/bin/sayoctl raw 0x08 00
```

## Notes

- Reports are 64 bytes.
- Packet format: `[id][cmd][data_len][data...][checksum]...`.
- `checksum` is a simple sum of bytes `0..(data_len+2)` modulo 256.
- `macros dump-script` writes a binary file; use `xxd script.bin | head` to view it.
- On some firmwares (including at least PID `0x0008`), the device exposes typed-string slots via cmd `0x0B` rather than cmd `0x0C`. `sayoctl strings ...` auto-detects this.
- `strings --translate` is a best-effort helper for UK/US layout symbol swaps when typing stored strings.

## AppImage notes (rough)

To build an AppImage for the GUI on Linux:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Builds build/SayoKeys-x86_64.AppImage
bash appimage/build_appimage.sh
```

The build script will:

- Build a standalone `sayogui` executable using PyInstaller
- Assemble an AppDir under `build/SayoKeys.AppDir`
- Download `appimagetool` (if missing)
- Produce `build/SayoKeys-x86_64.AppImage`
