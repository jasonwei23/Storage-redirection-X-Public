//! 后端路径的 init 命名空间覆盖挂载感知解析。
//!
//! 背景（真机 2026-10-19，HyperOS 应用商店 speed-install，`error=3`）：
//! HyperOS 会在系统命名空间把 `/data/apk-tmp/<pkg>/download` bind 到
//! `/data/media/<user>/Android/data/<pkg>/files/.siexternal`。这个 bind 位于
//! MediaProvider 与共享宿主会话（见 `fuse_host.rs` 的 `MS_SLAVE` 说明）的传播域内，
//! 但**不在应用命名空间里**。scoped FUSE 会话 worker 跟随应用命名空间服务
//! （挂载 worker 先 setns 再挂载），按普通路径解析 `/data/media/...` 后端时落
//! 到被 bind 遮蔽之前的真实目录：下载侧写入真实目录、商店校验侧经宿主/MP 读到
//! bind 目标 apk-tmp，两侧各执一份物理目录，商店读不到自己刚下载的文件。
//!
//! 修法：`/data/media/...` 后端路径解析前查 **init 命名空间**（`/proc/1/root`
//! 代表的挂载视图，即系统挂载授权方工作的地方）里是否有覆盖该路径的挂载；命中
//! 则把后端改写到覆盖挂载的物理源路径，使 scoped 会话的写侧与宿主/MP 的读侧
//! 汇聚到同一物理目录。无覆盖挂载时返回 `None`，路径保持原样——CI 场景与既有
//! 测试的后端路径断言不受任何影响。
//!
//! 改写到物理源路径（而不是 `/proc/1/root/...` 前缀）的原因：日志、监视台账与
//! 路径断言里出现的是真实落盘位置，可直接与真机 `ls`/`find` 证据互证；同时
//! `/proc/1/root` 前缀会让路径字符串随诊断上下文漂移，难以比较。
//!
//! 属主安全：覆盖目标（apk-tmp 目录树）由系统按下载方应用属主自管，本模块只做
//! **路径改写**，不改写既有节点的属主与权限；调用方（`ensure_parent_for_backend`）
//! 据此对覆盖路径跳过既有目录的元数据修复。

use crate::platform::mountinfo::{parse_entry, unescape_field};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// mountinfo 快照刷新间隔。HyperOS 的下载 bind 随下载任务创建与拆除，1 秒粒度
/// 足够跟上生命周期，同时把解析开销摊薄到可忽略（多线程共享同一份快照）。
const SNAPSHOT_TTL: Duration = Duration::from_secs(1);

/// 后端树的根前缀：覆盖判定只服务 `/data/media/...` 物理后端。
const BACKEND_TREE_PREFIX: &str = "/data/media";

/// 伪文件系统不承载后端数据，覆盖判定没有意义；`fuse` 前缀另行整族排除
/// （含 `fuse.srx` 本模块会话）。
const EXCLUDED_FS_TYPES: [&str; 10] = [
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "selinuxfs",
    "tracefs",
    "debugfs",
    "bpf",
    "functionfs",
    "configfs",
];

#[derive(Clone)]
struct OverlayMount {
    /// 设备号（`major:minor`），用于寻找该文件系统根挂载点。
    dev: String,
    /// init 视图中的挂载点（已展开八进制转义），如
    /// `/data/media/0/Android/data/com.xiaomi.market/files/.siexternal`。
    mount_point: String,
    /// 覆盖挂载在文件系统内的根（已展开转义），如
    /// `/apk-tmp/com.xiaomi.market/download`。
    root_in_fs: String,
}

#[derive(Default)]
struct Snapshot {
    /// `/data` 子树内的覆盖挂载候选（按 mountinfo 文件序）。
    overlays: Vec<OverlayMount>,
    /// 设备号 → 该文件系统根（`root=="/"`）的挂载点，如 `254:60 → /data`。
    fs_roots: HashMap<String, String>,
}

static SNAPSHOT: Mutex<Option<(Instant, Arc<Snapshot>)>> = Mutex::new(None);

fn load_snapshot() -> Snapshot {
    let mut snapshot = Snapshot::default();
    let Ok(content) = std::fs::read_to_string("/proc/1/mountinfo") else {
        // 非 Android 环境（本地测试）或权限受限：视为无覆盖挂载，路径保持原样。
        return snapshot;
    };
    for line in content.lines() {
        let Some(entry) = parse_entry(line) else {
            continue;
        };
        let is_virtual = EXCLUDED_FS_TYPES.contains(&entry.fs_type)
            || entry.fs_type.starts_with("fuse")
            || entry.fs_type.starts_with("sdcardfs");
        if is_virtual {
            continue;
        }
        let dev = entry.dev.to_string();
        let target = unescape_field(entry.target);
        let root_in_fs = unescape_field(entry.root);
        if root_in_fs == "/" && !snapshot.fs_roots.contains_key(&dev) {
            snapshot.fs_roots.insert(dev.clone(), target.clone());
        }
        // 只登记可能遮蔽 `/data/media` 后端的挂载点（含 `/data/media` 本身）。
        if target == "/data/media" || target.starts_with("/data/media/") {
            snapshot.overlays.push(OverlayMount {
                dev,
                mount_point: target,
                root_in_fs,
            });
        }
    }
    snapshot
}

fn cached_snapshot() -> Arc<Snapshot> {
    let mut guard = SNAPSHOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((fetched_at, snapshot)) = guard.as_ref()
        && fetched_at.elapsed() < SNAPSHOT_TTL
    {
        return snapshot.clone();
    }
    let snapshot = Arc::new(load_snapshot());
    *guard = Some((Instant::now(), snapshot.clone()));
    snapshot
}

/// 组件级前缀判断：`prefix == path` 或 `path` 位于 `prefix` 目录之下。
fn is_component_prefix(prefix: &str, path: &str) -> bool {
    if prefix == path {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    path.len() > prefix.len() && path.starts_with(prefix) && path.as_bytes()[prefix.len()] == b'/'
}

fn join_fs_path(fs_root: &str, root_in_fs: &str, rest: &str) -> String {
    let mut out = String::with_capacity(fs_root.len() + root_in_fs.len() + rest.len() + 1);
    out.push_str(fs_root.trim_end_matches('/'));
    let trimmed_root = root_in_fs.trim_end_matches('/');
    if !trimmed_root.is_empty() {
        if !trimmed_root.starts_with('/') {
            out.push('/');
        }
        out.push_str(trimmed_root);
    }
    // rest 来自后端路径去掉挂载点前缀的剩余部分：要么为空，要么以 '/' 开头。
    out.push_str(rest);
    out
}

static LAST_LOGGED_OVERLAY: Mutex<Option<String>> = Mutex::new(None);

/// 解析 `/data/media/...` 后端路径在 init 命名空间视图下的物理源路径。
///
/// 返回 `None` 表示无覆盖挂载或改写结果与原路径相同（恒等映射），调用方按
/// 原路径处理即可。改写仅在命中覆盖挂载时发生，稳态（无 bind）下零路径变化。
pub(super) fn overlay_backend_path(backend: &Path) -> Option<PathBuf> {
    let backend_text = backend.to_str()?;
    if !is_component_prefix(BACKEND_TREE_PREFIX, backend_text) {
        return None;
    }
    let snapshot = cached_snapshot();
    resolve_with_snapshot(backend_text, &snapshot)
}

/// 与 [`overlay_backend_path`] 相同，但绕过快照 TTL 强制重读 init mountinfo。
///
/// 仅供新建入口（create/mkdir）使用：HyperOS 的下载 bind 在任务入队瞬间创建，
/// 1 秒快照可能刚好错过，导致首次 CREATE 落到被遮蔽的真实目录、整次下载与
/// 商店校验读写分裂。新建是低频操作，重读 mountinfo 的开销可以接受。
pub(super) fn overlay_backend_path_fresh(backend: &Path) -> Option<PathBuf> {
    let backend_text = backend.to_str()?;
    if !is_component_prefix(BACKEND_TREE_PREFIX, backend_text) {
        return None;
    }
    let snapshot = Arc::new(load_snapshot());
    if let Some(slot) = SNAPSHOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_mut()
    {
        *slot = (Instant::now(), snapshot.clone());
    }
    resolve_with_snapshot(backend_text, &snapshot)
}

fn resolve_with_snapshot(backend_text: &str, snapshot: &Snapshot) -> Option<PathBuf> {
    // 最长挂载点优先：同一路径可能被多层嵌套 bind 逐级覆盖，最上层的才是可见层。
    let mut best: Option<&OverlayMount> = None;
    for mount in &snapshot.overlays {
        if !is_component_prefix(&mount.mount_point, backend_text) {
            continue;
        }
        let better = match best {
            Some(current) => mount.mount_point.len() > current.mount_point.len(),
            None => true,
        };
        if better {
            best = Some(mount);
        }
    }
    let mount = best?;
    let fs_root = snapshot.fs_roots.get(&mount.dev)?;
    let rest = &backend_text[mount.mount_point.len()..];
    let source = join_fs_path(fs_root, &mount.root_in_fs, rest);
    if source == backend_text {
        return None;
    }
    log_rewrite_once(&mount.mount_point, &source);
    Some(PathBuf::from(source))
}

/// 改写首次发生（或覆盖点变化）时留一条 debug 痕迹；同一覆盖点只记一次，避免
/// 下载期数千次路径解析刷屏。
fn log_rewrite_once(mount_point: &str, source: &str) {
    let mut guard = LAST_LOGGED_OVERLAY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.as_deref() == Some(mount_point) {
        return;
    }
    log::debug!(
        "fuse backend overlay rewrite mount_point={} source_prefix={}",
        mount_point,
        source
    );
    *guard = Some(mount_point.to_string());
}
