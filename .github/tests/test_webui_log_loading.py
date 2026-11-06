"""通过真实 JS 与 shell 快照验证大量日志不会撑大页面输入。"""

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WebUiLogLoadingTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "需要 Node 执行 WebUI 日志回归")
    def test_snapshot_loading_and_refresh_order(self):
        result = subprocess.run(
            ["node", str(ROOT / ".github/tests/harness/webui_log_loading.js")],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("刷新顺序回归通过", result.stdout)


if __name__ == "__main__":
    unittest.main()
