"""执行真实采集函数，覆盖进程预算耗尽后故障应用被遗漏的情况。"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "assets/zygisk_module/service.d/diagnostic_archive.sh"


class DiagnosticProcCaptureTests(unittest.TestCase):
    def run_selection(self, service_count: int, configured: bool = True, webview: bool = False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            apps = root / "apps"
            state.mkdir()
            apps.mkdir()
            packages = [f"com.sample.service{i:03}" for i in range(service_count)]
            packages.append("org.sample.reader")
            candidates = packages + (["com.sample.webview"] if webview else [])
            (state / "package-candidates.txt").write_text("\n".join(candidates) + "\n")
            processes = ["PID NAME"]
            processes.extend(
                f"{1000 + index} {name}" for index, name in enumerate(packages)
            )
            processes.append("9001 org.sample.reader:worker")
            if webview:
                processes.append("9002 com.sample.webview:sandboxed_process0")
            (state / "process-names.txt").write_text("\n".join(processes) + "\n")
            if configured:
                (apps / "org.sample.reader.json").write_text("{}")
            definitions = SCRIPT.read_text().split('\nstage="$1"\n', 1)[0]
            # 只替换设备 I/O；排序、去重、预算和索引仍执行生产实现。
            harness = definitions + r'''
STATE_DIR="$1/state"
APPS_CONFIG_DIR="$1/apps"
update_progress() { :; }
pidof() { :; }
collect_proc_for_pid() {
  printf '%s|%s|%s\n' "$2" "$1" "$3" >> "$STATE_DIR/captured.txt"
}
collect_relevant_proc_state
'''
            subprocess.run(
                ["sh", "-c", harness, "diagnostic-test", str(root)],
                check=True, capture_output=True, text=True, timeout=10,
            )
            captured = [
                line.split("|")
                for line in (state / "captured.txt").read_text().splitlines()
            ]
            return captured, (state / "package-pids.txt").read_text()

    def test_configured_main_process_precedes_background_services(self):
        captured, index = self.run_selection(18)
        self.assertEqual(captured[0], ["org.sample.reader", "1018", "true"])
        self.assertEqual(len(captured), 20)
        self.assertEqual(sum(row[2] == "true" for row in captured), 12)
        self.assertIn(["org.sample.reader", "9001", "false"], captured)
        self.assertIn("org.sample.reader 9001\n", index)

    def test_snapshot_budget_keeps_complete_index(self):
        captured, index = self.run_selection(70)
        self.assertEqual(captured[0], ["org.sample.reader", "1070", "true"])
        self.assertEqual(len(captured), 64)
        self.assertEqual(index.count("reason=limit limit=64"), 8)
        self.assertIn("org.sample.reader 9001\n", index)

    def test_empty_config_directory_still_matches_candidate_processes(self):
        captured, _ = self.run_selection(18, configured=False)
        self.assertEqual(len(captured), 20)
        self.assertIn(["org.sample.reader", "1018", "false"], captured)

    def test_repeated_candidate_does_not_consume_snapshot_budget(self):
        # 同一进程可能同时命中配置候选与隔离进程规则，按 pid 只保留一次。
        captured, _ = self.run_selection(1, webview=True)
        self.assertEqual(len(captured), 4)
        self.assertEqual(len({row[1] for row in captured}), len(captured))

    def test_snapshot_without_fd_collection_keeps_mounts_and_threads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            definitions = SCRIPT.read_text().split('\nstage="$1"\n', 1)[0]
            harness = definitions + r'''
PROC_DIR="$1"
collect_proc_for_pid "$2" org.sample.reader false
'''
            # 使用当前测试进程的 /proc，验证精简采集没有访问 fd 目录。
            subprocess.run(
                ["sh", "-c", harness, "diagnostic-test", str(root), str(os.getpid())],
                check=True, capture_output=True, text=True, timeout=10,
            )
            prefix = root / f"org.sample.reader_{os.getpid()}"
            self.assertTrue(Path(f"{prefix}-status.txt").read_text())
            self.assertTrue(Path(f"{prefix}-mountinfo.txt").read_text())
            self.assertIn("## task", Path(f"{prefix}-threads.txt").read_text())
            self.assertFalse(Path(f"{prefix}-fd.txt").exists())


if __name__ == "__main__":
    unittest.main()
