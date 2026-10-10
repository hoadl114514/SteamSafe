from __future__ import annotations
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import threading

from sentinel import VERSION


def asset_dir():
    return Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "assets"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--background", action="store_true")
    parser.add_argument("--launch", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--state-dir", type=Path, help="测试或便携配置目录")
    parser.add_argument("--smoke-test", type=Path, help="离屏启动界面并写入测试结果；不扫描 Steam")
    args = parser.parse_args()
    from sentinel.selfguard import startup_self_check
    self_checked = startup_self_check()
    if args.self_test:
        from tests.test_security import run_self_tests
        result = run_self_tests()
        if args.state_dir:
            args.state_dir.mkdir(parents=True, exist_ok=True)
            (args.state_dir / "self-test.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0 if result["successful"] else 1
    if args.smoke_test:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtCore import QObject, Signal, QTimer, Qt
    from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap, QFont, QAction, QFontDatabase
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
        QHBoxLayout, QLabel, QLineEdit, QPushButton, QCheckBox, QTextEdit,
        QFileDialog, QMessageBox, QSystemTrayIcon, QMenu, QGroupBox)
    from sentinel.core import atomic_json
    from sentinel.engine import Engine
    from sentinel import windows

    app = QApplication(sys.argv[:1])
    if args.smoke_test:
        fonts = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Fonts"
        for name in ("segoeui.ttf", "msyh.ttc", "msyhbd.ttc"):
            if (fonts / name).exists():
                QFontDatabase.addApplicationFont(str(fonts / name))
    app.setApplicationName("SteamSafe Beta")
    app.setQuitOnLastWindowClosed(False)
    # Administrator mode uses protected install/data folders; test modes never protect Steam.
    if sys.platform == "win32" and not args.self_test and not args.smoke_test:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            QMessageBox.warning(None, "需要管理员", "请通过管理员安装器启动此版本，UAC 请求需允许。")
            return 1
        from sentinel.privilege import protected_state,verify_protected_directory,set_admin_default_owner
        set_admin_default_owner()
        if getattr(sys,'frozen',False):
            verify_protected_directory(Path(sys.executable).parent)
            for file in Path(sys.executable).parent.rglob('*'):
                if file.is_file():verify_protected_directory(file)
        if args.state_dir:
            raise RuntimeError('管理员实际运行不接受外部数据目录参数')
        state = protected_state()
    else:
        state = args.state_dir or Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SteamSafeBeta"
    state.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(state / "sentinel.log", maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[handler], format="%(asctime)s %(levelname)s %(message)s")
    mutex = windows.acquire_mutex(state)
    if not mutex:
        QMessageBox.information(None, "SteamSafe", "软件已在运行，请从系统托盘打开。")
        return 0

    settings = {"steam_path": str(windows.discover_steam() or ""), "root_confirmed":False, "monitor": True,
                "auto_repair": True, "stop_on_mismatch": True, "module_monitor": True}
    if (state / "settings.json").exists():
        try:
            saved = json.loads((state / "settings.json").read_text(encoding="utf-8"))
            settings.update({k: saved[k] for k in settings if k in saved})
        except Exception:
            logging.exception("Invalid settings")
    if args.smoke_test:
        settings["monitor"] = False

    class Signals(QObject):
        log = Signal(str)
        alert = Signal(str)
        result = Signal(dict)
        busy = Signal(bool)

    signals = Signals()
    try:
        engine = Engine(asset_dir(), state, settings, signals)
    except Exception as e:
        QMessageBox.critical(None, "启动失败", f"发行基线验证失败，保护未启动：{e}")
        return 1

    image = QPixmap(64, 64)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#42d8bd"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(4, 4, 56, 56, 16, 16)
    painter.setPen(QColor("#102021"))
    painter.setFont(QFont("Segoe UI", 31, QFont.Weight.Bold))
    painter.drawText(image.rect(), Qt.AlignmentFlag.AlignCenter, "S")
    painter.end()
    icon = QIcon(image)
    app.setWindowIcon(icon)

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"SteamSafe · {VERSION}")
            self.resize(900, 720)
            widget = QWidget()
            self.setCentralWidget(widget)
            layout = QVBoxLayout(widget)
            layout.setContentsMargins(28, 24, 28, 24)
            layout.setSpacing(16)
            title = QLabel("STEAMSAFE")
            title.setObjectName("title")
            layout.addWidget(title)
            subtitle = QLabel("启动前校验  ·  版本感知检查  ·  隔离与恢复")
            subtitle.setObjectName("subtitle")
            layout.addWidget(subtitle)
            self.status = QLabel("等待检查")
            self.status.setObjectName("status")
            layout.addWidget(self.status)
            self.detail = QLabel(f"发行基线：{engine.seed['version']} · {len(engine.seed['files'])} 个程序／界面文件")
            self.detail.setWordWrap(True)
            layout.addWidget(self.detail)
            row = QHBoxLayout()
            self.path = QLineEdit(str(settings["steam_path"]))
            self.path.setPlaceholderText("选择包含 steam.exe 的安装目录")
            row.addWidget(self.path, 1)
            self.browse_button = QPushButton("选择目录")
            self.browse_button.clicked.connect(self.browse)
            row.addWidget(self.browse_button)
            layout.addLayout(row)
            self.path.editingFinished.connect(self.save_path)
            buttons = QHBoxLayout()
            self.check = QPushButton("立即检查")
            self.launch = QPushButton("校验并启动 Steam")
            self.launch.setObjectName("primary")
            self.repair = QPushButton("修复已确认异常")
            for button, command in ((self.check, "scan"), (self.launch, "launch"), (self.repair, "repair")):
                button.clicked.connect(lambda checked=False, c=command: self.enqueue(c))
                buttons.addWidget(button)
            layout.addLayout(buttons)
            options = QGroupBox("后台保护")
            self.options = options
            opt = QVBoxLayout(options)
            self.monitor = self.checkbox(opt, "后台即时检查侧载 DLL、配置、界面脚本及文件修改", "monitor")
            self.stop = self.checkbox(opt, "命中高风险客户端修改后立即结束 Steam", "stop_on_mismatch")
            self.auto = self.checkbox(opt, "Steam 完全退出后自动隔离备份并修复", "auto_repair")
            self.modules = self.checkbox(opt, "检查外部加载模块（仅提示，不能保证阻止注入）", "module_monitor")
            self.startup = QCheckBox("登录 Windows 后启动并常驻托盘")
            self.startup.setChecked(windows.autostart_enabled())
            self.startup.toggled.connect(self.autostart)
            opt.addWidget(self.startup)
            layout.addWidget(options)
            self.monitor_status = QLabel()
            self.monitor_status.setWordWrap(True)
            layout.addWidget(self.monitor_status)
            self.monitor_timer = QTimer(self)
            self.monitor_timer.timeout.connect(self.refresh_monitor_status)
            self.monitor_timer.start(1000)
            self.refresh_monitor_status()
            self.logs = QTextEdit()
            self.logs.setReadOnly(True)
            self.logs.document().setMaximumBlockCount(600)
            layout.addWidget(self.logs, 1)
            footer = QHBoxLayout()
            report = QPushButton("导出检查报告")
            report.clicked.connect(self.export)
            rollback = QPushButton("回滚最近修复")
            rollback.clicked.connect(self.confirm_rollback)
            hide = QPushButton("最小化到托盘")
            hide.clicked.connect(self.hide_to_tray)
            footer.addWidget(report)
            footer.addWidget(rollback)
            release_hold=QPushButton('复查并解除复发拦截')
            release_hold.clicked.connect(lambda: self.enqueue('clear-reinfection'))
            footer.addWidget(release_hold)
            footer.addStretch()
            footer.addWidget(hide)
            layout.addLayout(footer)
            support=QPushButton('在系统浏览器打开官方账号安全指引')
            def open_support():
                import ctypes
                buffer=ctypes.create_unicode_buffer(32768)
                ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,len(buffer))
                windows.launch_as_desktop_user([str(Path(buffer.value)/'explorer.exe'),
                    'https://help.steampowered.com/en/faqs/view/6639-EB3C-EC79-FF60'],Path(buffer.value))
            support.clicked.connect(open_support)
            layout.addWidget(support)
            note = QLabel("Beta 支持 Windows 10/11 x64 的 Steam 正式版。首次运行请先检查；从其他入口启动仅能事后监测。")
            note.setWordWrap(True)
            note.setObjectName("subtitle")
            layout.addWidget(note)
            signals.log.connect(self.append)
            signals.alert.connect(self.alert)
            signals.result.connect(self.result)
            signals.busy.connect(self.busy)
            self.tray = QSystemTrayIcon(icon, self)
            menu = QMenu()
            for label, callback in (("打开主界面", self.show_normal), ("立即检查", lambda: self.enqueue("scan")),
                                    ("校验并启动 Steam", lambda: self.enqueue("launch")), ("退出", self.quit)):
                action = QAction(label, self)
                action.triggered.connect(callback)
                menu.addAction(action)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(lambda reason: self.show_normal() if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None)
            if not args.smoke_test:
                self.tray.show()
            self.append("保护已准备。联网仅请求官方更新 CDN，不上传文件、账号或扫描报告。")
            self.append(f"启动自检通过：{self_checked} 个发行文件；自签名证书已固定。")
            self.warning_box = None

        def refresh_monitor_status(self):
            if args.smoke_test:
                text = '后台监测：界面诊断模式，不执行真实检测'
            elif not settings['monitor']:
                text = '后台监测：已关闭'
            elif not settings['root_confirmed']:
                text = '后台监测：等待确认 Steam 目录，请点击“立即检查”'
            elif engine.guard_state == 'failed' or engine.worker_state == 'failed':
                text = '后台监测：线程启动失败，请查看错误日志'
            elif engine.guard_state != 'running' or engine.worker_state != 'running':
                text = '后台监测：线程正在启动'
            else:
                text = '后台监测：即时文件守护与完整校验线程已就绪'
            self.monitor_status.setText(text)

        def checkbox(self, layout, text, key):
            cb = QCheckBox(text)
            cb.setChecked(bool(settings[key]))
            cb.toggled.connect(lambda value: self.change(key, value))
            layout.addWidget(cb)
            return cb

        def change(self, key, value):
            settings[key] = value
            atomic_json(state / "settings.json", settings)

        def save_path(self):
            value=self.path.text().strip().strip('"')
            if value!=settings['steam_path']:self.change('root_confirmed',False)
            self.change("steam_path", value)

        def browse(self):
            chosen = QFileDialog.getExistingDirectory(self, "选择 Steam 安装目录", self.path.text())
            if chosen:
                self.path.setText(chosen)
                self.save_path()

        def enqueue(self, command):
            self.save_path()
            self.change('root_confirmed',True)
            self.busy(True)
            engine.commands.put(command)

        def busy(self, value):
            for button in (self.check, self.launch, self.repair):
                button.setEnabled(not value)
            self.path.setEnabled(not value)
            self.browse_button.setEnabled(not value)
            self.options.setEnabled(not value)
            if value:
                self.status.setText("正在检查 / 处理…")

        def append(self, text):
            import time
            self.logs.append(f"[{time.strftime('%H:%M:%S')}] {text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')}")

        def alert(self, text):
            self.status.setText("存在待核对项 / 操作未完成")
            self.status.setStyleSheet("color:#ffc77d;")
            self.tray.showMessage("SteamSafe · 需要注意", text[:240], QSystemTrayIcon.MessageIcon.Warning, 10000)
            if text.startswith(("客户端修改／", "异常已检出", "隔离／修复已完成", "异常尚未完全处理")):
                if self.warning_box is None:
                    self.warning_box = QMessageBox(QMessageBox.Icon.Warning, "Steam 客户端安全警告", text,
                        QMessageBox.StandardButton.Ok, self)
                self.warning_box.setText(text)
                self.warning_box.show()
                self.warning_box.raise_()

        def result(self, value):
            labels = {"clean": "客户端检查通过", "blocked": "客户端异常 · 启动已阻止", "mismatch": "发现文件完整性异常", "updating": "更新状态待确认",
                      "unknown": "版本尚未验证", "unverified": "检查未完成"}
            self.status.setText(labels.get(value["state"], value["state"]))
            color = "#42d8bd" if value["state"] == "clean" and not value["findings"] else "#ffc77d"
            self.status.setStyleSheet(f"color:{color};")
            self.detail.setText(f"安装版本：{value['version'] or '未确认'}  ·  最新版本：{value['latest'] or '未联网确认'}\n"
                                f"{value['detail']}  ·  检查 {value['checked']} 个文件")
            if value["findings"] and value["state"] == "clean":
                self.status.setText("文件校验完成 · 存在待核对项")

        def autostart(self, enabled):
            try:
                windows.set_autostart(enabled)
                self.append("已启用登录自启。请勿移动 EXE；移动后重新设置。" if enabled else "已关闭登录自启。")
            except Exception as e:
                QMessageBox.warning(self, "设置失败", str(e))

        def export(self):
            report = state / "last-report.json"
            if not report.exists():
                QMessageBox.information(self, "导出报告", "请先完成一次检查。")
                return
            dest, _ = QFileDialog.getSaveFileName(self, "保存检查报告", "SteamSafe-report.json", "JSON (*.json)")
            if dest:
                Path(dest).write_bytes(report.read_bytes())

        def confirm_rollback(self):
            if QMessageBox.question(self, "回滚修复", "回滚会恢复修复前的原文件，这些文件可能不可信。请先退出 Steam。是否继续？") == QMessageBox.StandardButton.Yes:
                self.enqueue("rollback")

        def show_normal(self):
            self.showNormal()
            self.raise_()
            self.activateWindow()

        def hide_to_tray(self):
            if QSystemTrayIcon.isSystemTrayAvailable():
                self.hide()
            else:
                self.showMinimized()

        def closeEvent(self, event):
            if args.smoke_test:
                event.accept()
            else:
                event.ignore()
                self.hide_to_tray()

        def quit(self):
            if not self.check.isEnabled():
                QMessageBox.information(self, "正在处理", "正在校验或修复，请待操作完成后退出，避免中断文件替换。")
                return
            engine.shutdown.set()
            self.tray.hide()
            app.quit()

    app.setStyleSheet("""
        QMainWindow,QWidget{background:#121c26;color:#e8f0f7;font-family:'Microsoft YaHei';font-size:13px;}
        QLabel#title{font-family:'Segoe UI';font-size:30px;font-weight:700;letter-spacing:2px;}
        QLabel#subtitle{color:#99afc2;font-size:12px;}
        QLabel#status{font-size:24px;font-weight:600;color:#42d8bd;padding:12px 0;}
        QLineEdit,QTextEdit{background:#0d151e;border:1px solid #304153;border-radius:8px;padding:10px;}
        QPushButton{background:#243545;border:1px solid #3b5265;border-radius:7px;padding:10px 16px;}
        QPushButton:hover{background:#304b5e;} QPushButton:disabled{color:#738594;background:#1a2632;}
        QPushButton#primary{background:#42d8bd;color:#102021;font-weight:600;}
        QGroupBox{border:1px solid #304153;border-radius:8px;margin-top:10px;padding:14px;}
        QGroupBox::title{subcontrol-origin:margin;left:14px;padding:0 5px;}
        QCheckBox{spacing:9px;padding:3px;} QMenu{background:#243545;}
    """)
    window = Window()
    if args.smoke_test:
        window.show()
        def finish_smoke():
            args.smoke_test.mkdir(parents=True, exist_ok=True)
            window.grab().save(str(args.smoke_test / "ui.png"))
            (args.smoke_test / "smoke.json").write_text(json.dumps({"ok": True, "version": VERSION,
                "baseline_version": engine.seed["version"], "files": len(engine.seed["files"]),
                "frozen": bool(getattr(sys, "frozen", False))}), encoding="utf-8")
            app.quit()
        QTimer.singleShot(500, finish_smoke)
    else:
        threading.Thread(target=engine.run, name="SteamSafeWorker", daemon=True).start()
        threading.Thread(target=engine.guard_run, name="SteamImmediateGuard", daemon=True).start()
        if not args.background or not QSystemTrayIcon.isSystemTrayAvailable() or not settings['root_confirmed']:
            window.show()
        if args.launch:
            window.enqueue("launch")
    return app.exec()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        error = traceback.format_exc()
        diagnostic = "--smoke-test" in sys.argv or "--self-test" in sys.argv
        if getattr(sys,'frozen',False) and not diagnostic:
            # Never turn a failed elevated startup into a write through an untrusted log path.
            path = None
        elif "--state-dir" in sys.argv:
            path = Path(sys.argv[sys.argv.index("--state-dir") + 1])
        else:
            path = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SteamSafeBeta"
        try:
            if path is not None:
                path.mkdir(parents=True, exist_ok=True)
                (path / "startup-error.txt").write_text(error, encoding="utf-8")
        except OSError:
            pass
        if sys.platform == "win32" and "--smoke-test" not in sys.argv and "--self-test" not in sys.argv:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, "启动失败：\n" + error[-1200:] + ("\n\n诊断路径：" + str(path / "startup-error.txt") if path else ''), "SteamSafe", 0x10)
        sys.exit(1)
