// 执行真实 WebUI 快照读取与页面加载，覆盖轮转、大量记录和迟到响应。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { execFileSync } = require("node:child_process");

const root = path.resolve(__dirname, "../../..");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "srx-log-read-"));
const viewer = {
  innerHTML: "", children: [], scrollTop: 0, clientHeight: 600, style: {},
  querySelectorAll: () => [],
};
const info = { textContent: "" };
const sandbox = {
  console, URL, AbortController, setTimeout, clearTimeout,
  requestAnimationFrame: () => 1,
  localStorage: { getItem: () => null, setItem: () => {} },
  window: {
    App: {}, matchMedia: () => ({ matches: false }), addEventListener: () => {},
    history: {}, location: { hash: "" },
  },
  document: {
    readyState: "loading", addEventListener: () => {}, querySelectorAll: () => [],
    querySelector: (selector) => selector === "#logViewer" ? viewer : selector === "#logInfo" ? info : null,
    createElement: () => ({ textContent: "", innerHTML: "" }),
    documentElement: { setAttribute: () => {} },
  },
  Theme: { showToast: () => {} },
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(root, "assets/zygisk_module/webroot/js/api.js"), "utf8"), sandbox);
// 只在夹具中暴露闭包，不为生产增加测试入口或替代业务方法。
const app = fs.readFileSync(path.join(root, "assets/zygisk_module/webroot/js/app.js"), "utf8");
vm.runInContext(app.replace('  if (window.__SRX_ENABLE_TEST_EXPORTS__) {',
  '  window.logFixture = { loadLogs, State };\n  if (window.__SRX_ENABLE_TEST_EXPORTS__) {'), sandbox);
const api = sandbox.window.Api;
const execBridge = api.exec;
const { loadLogs, State } = sandbox.window.logFixture;
const filters = { excluded_paths: [], excluded_operations: [] };

function line(number) {
  return `2026-10-20 23:18:00|com.example.app|com.example.app|CREATE|/storage/emulated/0/Pictures/${number}.jpg|op=create|ret=0|errno=0|event_role=request|identify_method=caller|identify_reliability=high`;
}

async function main() {
  const base = path.join(directory, "记录 ' 日志.log");
  fs.writeFileSync(base + ".2", Array.from({ length: 20000 }, (_, i) => line(i)).join("\n") + "\n");
  fs.writeFileSync(base + ".1", Array.from({ length: 20000 }, (_, i) => line(20000 + i)).join("\n") + "\n");
  fs.writeFileSync(base, Array.from({ length: 250 }, (_, i) => line(40000 + i)).join("\n") + "\n");
  fs.writeFileSync(base + ".rotate.lock", "不应读取\n");
  api.exec = async (command, options) => {
    assert.equal(options.timeoutMs, 10000);
    return execFileSync("sh", ["-c", command], { encoding: "utf8" }).trim();
  };
  const snapshot = await api.readFileWithBackups(base);
  const rows = snapshot.split("\n");
  assert.equal(rows.length, 1000);
  assert.equal(rows[0], line(39250));
  assert.equal(rows.at(-1), line(40249));
  // 当前文件为空或轮转时消失，仍从备份补齐最新记录。
  fs.unlinkSync(base);
  const rotated = (await api.readFileWithBackups(base)).split("\n");
  assert.equal(rotated.length, 1000);
  assert.equal(rotated.at(-1), line(39999));
  api.exec = async () => { throw new Error("读取超时"); };
  await assert.rejects(api.readFileWithBackups(base), /读取超时/);

  // 桥接始终不回调时，实际 NativeBridge 也必须按传入超时结束。
  sandbox.ksu = { exec: () => {} };
  sandbox.setTimeout = (callback, delay) => setTimeout(callback, Math.min(delay, 5));
  api.exec = execBridge;
  await assert.rejects(api.readFileWithBackups(base), /timed out/);
  let bridgeCalls = 0;
  sandbox.ksu.exec = () => {
    if (++bridgeCalls === 1) throw new Error("切换兼容签名");
  };
  await assert.rejects(api.readFileWithBackups(base), /timed out/);
  assert.equal(bridgeCalls, 2);
  delete sandbox.ksu;
  sandbox.setTimeout = setTimeout;

  api.exec = async (_, options) => { assert.equal(options.timeoutMs, 5000); return "{}"; };
  await api.readMonitorFilters({ force: true, timeoutMs: 5000 });
  await api.ensureLogCollectors();

  // 采集器维护不返回，也不能阻止快照显示。
  api.ensureLogCollectors = () => new Promise(() => {});
  api.readMonitorFilters = async () => filters;
  api.populatePackageInfo = () => {};
  api.readFileWithBackups = async () => snapshot;
  await loadLogs();
  assert.equal(State.logEntries.length, 1000);
  assert.equal(State.logEntries[0].path, "/storage/emulated/0/Pictures/40249.jpg");
  assert(!viewer.innerHTML.includes("加载日志..."));
  assert(info.textContent.includes("最多读取1000行"));

  // 较早请求后返回，不能覆盖最近一次刷新结果。
  let resolveOld;
  api.readFileWithBackups = () => new Promise((resolve) => { resolveOld = resolve; });
  const old = loadLogs();
  api.readFileWithBackups = async () => line("new");
  await loadLogs();
  resolveOld(line("old"));
  await old;
  assert.equal(State.logEntries[0].path, "/storage/emulated/0/Pictures/new.jpg");
  api.readFileWithBackups = async () => { throw new Error("读取超时"); };
  await loadLogs();
  assert(viewer.innerHTML.includes("日志读取失败，请下拉重试"));
  console.log("WebUI 日志快照、维护阻塞和刷新顺序回归通过");
}

// 未完成的 Promise 本身不会保持 Node 存活，必须防止挂起被误报为成功。
const watchdog = setTimeout(() => {
  console.error("日志加载回归未按时完成");
  process.exitCode = 1;
}, 5000);
main().catch((error) => { console.error(error); process.exitCode = 1; })
  .finally(() => {
    clearTimeout(watchdog);
    fs.rmSync(directory, { recursive: true, force: true });
  });
