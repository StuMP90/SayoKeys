#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPIMAGE_DIR="$ROOT_DIR/appimage"
BUILD_DIR="$ROOT_DIR/build"
APPDIR="$BUILD_DIR/SayoKeys.AppDir"
DIST_DIR="$BUILD_DIR/dist"

PYTHON_BIN="$ROOT_DIR/.venv/bin/python3"
PIP_BIN="$ROOT_DIR/.venv/bin/pip"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Expected venv python at $PYTHON_BIN" >&2
  exit 1
fi

mkdir -p "$BUILD_DIR" "$DIST_DIR"

# 1) Build a standalone GUI binary with PyInstaller
"$PIP_BIN" install -q pyinstaller

rm -rf "$BUILD_DIR/pyinstaller" "$APPDIR"
mkdir -p "$BUILD_DIR/pyinstaller"

ENTRY_SCRIPT="$BUILD_DIR/pyinstaller/sayogui_entry.py"
cat >"$ENTRY_SCRIPT" <<'PY'
from sayoctl.gui import main


if __name__ == "__main__":
    raise SystemExit(main())
PY

"$PYTHON_BIN" -m PyInstaller \
  --clean \
  --noconfirm \
  --name sayogui \
  --onefile \
  --windowed \
  --distpath "$DIST_DIR" \
  --workpath "$BUILD_DIR/pyinstaller" \
  "$ENTRY_SCRIPT"

# 2) Assemble AppDir
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/scalable/apps"

if [[ -f "$DIST_DIR/sayogui" ]]; then
  cp "$DIST_DIR/sayogui" "$APPDIR/usr/bin/sayogui"
elif [[ -x "$DIST_DIR/sayogui/sayogui" ]]; then
  cp "$DIST_DIR/sayogui/sayogui" "$APPDIR/usr/bin/sayogui"
else
  echo "Unable to find PyInstaller output at $DIST_DIR/sayogui" >&2
  exit 1
fi
cp "$APPIMAGE_DIR/sayogui.desktop" "$APPDIR/usr/share/applications/sayogui.desktop"
cp "$APPIMAGE_DIR/sayogui.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/sayogui.svg"

# AppImage entrypoints
cp "$APPIMAGE_DIR/AppRun" "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun" "$APPDIR/usr/bin/sayogui"
ln -sf "usr/share/icons/hicolor/scalable/apps/sayogui.svg" "$APPDIR/sayogui.svg"
ln -sf "usr/share/applications/sayogui.desktop" "$APPDIR/sayogui.desktop"

# 3) Build AppImage
# appimagetool is typically distributed as an AppImage itself.
APPIMAGETOOL="$BUILD_DIR/appimagetool-x86_64.AppImage"
if [[ ! -x "$APPIMAGETOOL" ]]; then
  echo "Downloading appimagetool..." >&2
  curl -L -o "$APPIMAGETOOL" "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
  chmod +x "$APPIMAGETOOL"
fi

OUTPUT="$BUILD_DIR/SayoKeys-x86_64.AppImage"
ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$OUTPUT"

echo "Built: $OUTPUT"
