"""自有缓存系统视图的请求门控与挂载生命周期回归。"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_mount_metadata_scope import function_body

ROOT = Path(__file__).resolve().parents[2]


class NativeCacheViewTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("rustc"), "需要 Rust 编译器")
    def test_monitor_and_explicit_rules_prevent_cache_bypass(self):
        source = (ROOT / "src/fuse_redirect/config.rs").read_text()
        trait_signature = "pub trait MountRequestFields "
        function_signature = "pub fn native_cache_restore_allowed<R: MountRequestFields + ?Sized>(request: &R) -> bool "
        definitions = (
            trait_signature + function_body(source, trait_signature) + "\n"
            + function_signature + function_body(source, function_signature) + "\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cache_policy.rs").write_text(definitions)
            shutil.copy(ROOT / ".github/tests/harness/native_cache_view.rs", root / "main.rs")
            subprocess.run(
                ["rustc", "--edition=2024", "-A", "dead_code", "-A", "private_bounds",
                 "-A", "private_interfaces", str(root / "main.rs"), "-o", str(root / "test")],
                check=True, capture_output=True, text=True, timeout=30,
            )
            subprocess.run([str(root / "test")], check=True, capture_output=True, timeout=10)

    def test_restore_follows_host_attach_and_precedes_state_and_identity(self):
        daemon = (ROOT / "src/daemon_mount.rs").read_text()
        restore = daemon.index("let restore_native_cache =")
        collect = daemon.index("mounted_targets.extend(planner.take_mounted_targets())", restore)
        persist = daemon.index("if !write_mount_state(request, plan", restore)
        identity = daemon.index("record_mount_identity(request", persist)
        self.assertLess(restore, collect)
        self.assertLess(collect, persist)
        self.assertLess(persist, identity)
        self.assertIn("detach_round_mount_targets(&mounted_targets)", daemon[persist:identity])
        companion = (ROOT / "src/lifecycle/companion_mount.rs").read_text()
        restore = companion.index("let restore_native_cache =")
        self.assertIn("native_cache_restore_allowed(request)", companion[restore:restore + 220])

    def test_restore_is_limited_to_existing_own_cache(self):
        source = (ROOT / "src/mount/apply.rs").read_text()
        body = function_body(source, "fn restore_own_private_directories(")
        self.assertIn('format!("Android/data/{}/cache", self.package_name)', body)
        self.assertIn('let is_native_cache = restore_native_cache && relative.ends_with("/cache")', body)
        self.assertIn("&& !is_native_cache", body)
        self.assertLess(body.index("if !backend_exists"), body.index("self.ensure_directory_exists"))
        self.assertIn("std::fs::symlink_metadata(&backend_source)", body)
        self.assertIn("mountinfo_has_own_private_restore_layer", body)
        self.assertIn("bind_own_private_restore", body)


if __name__ == "__main__":
    unittest.main()
