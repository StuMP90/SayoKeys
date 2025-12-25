from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from PySide6 import QtCore, QtWidgets

from .protocol import SayoDevice, SayoProtocolError, enumerate_sayo_devices


_UK_US_SYMBOL_SWAP = {
    "#": "£",
    "£": "#",
    "@": '"',
    '"': "@",
}


def _translate_uk_to_us(text: str) -> str:
    return "".join(_UK_US_SYMBOL_SWAP.get(ch, ch) for ch in text)


@dataclass(frozen=True)
class DeviceChoice:
    label: str
    path: str


class _Invoker(QtCore.QObject):
    finished = QtCore.Signal(object, object, object)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Sayo Keys")

        self._thread_pool = []

        self._device_path: Optional[str] = None
        self._key_types: dict[int, int] = {}

        root = QtWidgets.QWidget()
        self.setCentralWidget(root)

        main = QtWidgets.QVBoxLayout(root)

        top = QtWidgets.QHBoxLayout()
        main.addLayout(top)

        self.device_combo = QtWidgets.QComboBox()
        top.addWidget(self.device_combo, 1)

        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        top.addWidget(self.refresh_btn)

        self.connect_btn = QtWidgets.QPushButton("Connect")
        top.addWidget(self.connect_btn)

        self.load_btn = QtWidgets.QPushButton("Load")
        self.load_btn.setEnabled(False)
        top.addWidget(self.load_btn)

        self.apply_btn = QtWidgets.QPushButton("Apply")
        self.apply_btn.setEnabled(False)
        top.addWidget(self.apply_btn)

        self.status = QtWidgets.QLabel("")
        main.addWidget(self.status)

        split = QtWidgets.QSplitter()
        split.setOrientation(QtCore.Qt.Orientation.Horizontal)
        main.addWidget(split, 1)

        keys_panel = QtWidgets.QWidget()
        keys_layout = QtWidgets.QFormLayout(keys_panel)
        keys_layout.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
        split.addWidget(keys_panel)

        strings_panel = QtWidgets.QWidget()
        strings_layout = QtWidgets.QFormLayout(strings_panel)
        strings_layout.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
        split.addWidget(strings_panel)

        self.key_enable_btns: dict[int, QtWidgets.QPushButton] = {}
        for i in range(8):
            btn = QtWidgets.QPushButton("Enable string")
            btn.setEnabled(False)
            btn.clicked.connect(lambda checked=False, n=i: self._enable_string_mode(n))
            keys_layout.addRow(f"Key {i + 1}", btn)
            self.key_enable_btns[i] = btn

        self.string_edits: dict[int, QtWidgets.QLineEdit] = {}
        for i in range(8):
            edit = QtWidgets.QLineEdit()
            edit.setEnabled(False)
            edit.setPlaceholderText(f"String {i}")
            strings_layout.addRow(f"String {i}", edit)
            self.string_edits[i] = edit

        self.refresh_btn.clicked.connect(self._refresh_devices)
        self.connect_btn.clicked.connect(self._connect_selected)
        self.load_btn.clicked.connect(self._load_from_device)
        self.apply_btn.clicked.connect(self._apply_strings)

        self._refresh_devices()

        self._invoker = _Invoker(self)
        self._invoker.finished.connect(self._deliver_from_worker)

    @QtCore.Slot(object, object, object)
    def _deliver_from_worker(self, on_done: object, res: object, err: object) -> None:
        if callable(on_done):
            on_done(res, err)

    def _set_status(self, text: str) -> None:
        self.status.setText(text)

    def _run_in_thread(self, fn: Callable[[], object], on_done: Callable[[object, Optional[BaseException]], None]) -> None:
        def _target() -> None:
            try:
                res = fn()
                err: Optional[BaseException] = None
            except BaseException as e:
                res = None
                err = e

            # Deliver result back to the Qt main thread.
            self._invoker.finished.emit(on_done, res, err)

        t = threading.Thread(target=_target, daemon=True, name="sayogui-worker")
        self._thread_pool.append(t)
        t.start()

    def _refresh_devices(self) -> None:
        self.device_combo.clear()
        devices = enumerate_sayo_devices()
        for d in devices:
            label = f"0x{d.vendor_id:04x}:0x{d.product_id:04x} {d.product_string or ''} ({d.path})"
            self.device_combo.addItem(label, d.path)
        if devices:
            self._set_status(f"Found {len(devices)} device(s)")
        else:
            self._set_status("No devices found")
        self._set_connected(False)

    def _set_connected(self, connected: bool) -> None:
        self.load_btn.setEnabled(connected)
        self.apply_btn.setEnabled(connected)
        for i in range(8):
            self.key_enable_btns[i].setEnabled(False)
            self.string_edits[i].setEnabled(False)
        if not connected:
            self._device_path = None
            self._key_types = {}

    def _connect_selected(self) -> None:
        path = self.device_combo.currentData()
        if not path:
            self._set_status("Select a device")
            return
        self._device_path = str(path)
        self._set_status(f"Selected {self._device_path}. Click Load.")
        self._set_connected(True)

    def _load_from_device(self) -> None:
        if not self._device_path:
            self._set_status("Not connected")
            return

        self._set_status("Loading keys and strings...")

        def _do() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
            with SayoDevice(self._device_path) as dev:
                keys = dev.list_keys()
                strings = [dev.get_string(i) for i in range(8)]
            return keys, strings

        def _done(res: object, err: Optional[BaseException]) -> None:
            if err is not None:
                self._handle_error(err)
                return
            keys, strings = res
            self._key_types = {}
            for entry in keys:
                n = int(entry.get("number", -1))
                if 0 <= n <= 7:
                    self._key_types[n] = int(entry.get("type", 0))

            for i in range(8):
                t = self._key_types.get(i, 0)
                if t == 0:
                    self.key_enable_btns[i].setEnabled(True)
                    self.key_enable_btns[i].setText("Enable string")
                elif t == 8:
                    self.key_enable_btns[i].setEnabled(False)
                    self.key_enable_btns[i].setText("String mode locked")
                else:
                    self.key_enable_btns[i].setEnabled(False)
                    self.key_enable_btns[i].setText(f"Type {t} (locked)")

            for s in strings:
                idx = int(s.get("number", -1))
                if 0 <= idx <= 7:
                    txt = s.get("text", "")
                    if isinstance(txt, str):
                        self.string_edits[idx].setText(_translate_uk_to_us(txt))

            for i in range(8):
                self.string_edits[i].setEnabled(True)

            self._set_status("Loaded")

        self._run_in_thread(_do, _done)

    def _enable_string_mode(self, index: int) -> None:
        if not self._device_path:
            self._set_status("Not connected")
            return
        if self._key_types.get(index, 0) != 0:
            return

        self._set_status(f"Enabling string mode for key {index + 1}...")

        def _do() -> dict[str, object]:
            with SayoDevice(self._device_path) as dev:
                return dev.set_key(number=index, key_type=8, values=[index, 0, 2, 0])

        def _done(res: object, err: Optional[BaseException]) -> None:
            if err is not None:
                self._handle_error(err)
                return
            self._key_types[index] = 8
            self.key_enable_btns[index].setEnabled(False)
            self.key_enable_btns[index].setText("String mode locked")
            self._set_status(f"Key {index + 1} is now string mode")

        self._run_in_thread(_do, _done)

    def _apply_strings(self) -> None:
        if not self._device_path:
            self._set_status("Not connected")
            return

        texts: dict[int, str] = {}
        for i in range(8):
            texts[i] = self.string_edits[i].text()

        self._set_status("Writing strings...")

        def _do() -> None:
            with SayoDevice(self._device_path) as dev:
                for i in range(8):
                    dev.set_string(number=i, text=_translate_uk_to_us(texts[i]), mode=0)
            return None

        def _done(res: object, err: Optional[BaseException]) -> None:
            if err is not None:
                self._handle_error(err)
                return
            self._set_status("Strings written")

        self._run_in_thread(_do, _done)

    def _handle_error(self, err: BaseException) -> None:
        if isinstance(err, SayoProtocolError):
            msg = str(err)
        else:
            msg = f"{type(err).__name__}: {err}"
        self._set_status(msg)
        QtWidgets.QMessageBox.critical(self, "Error", msg)


def main() -> int:
    # When launched under `sudo`, the root environment often lacks a working
    # session DBus, and Qt's GNOME platform theme plugin can crash.
    # Disabling the platform theme avoids that integration path.
    os.environ["QT_QPA_PLATFORMTHEME"] = "xdgdesktopportal"
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.resize(900, 400)
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
