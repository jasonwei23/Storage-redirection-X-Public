//! 自动路径元数据修正的实验开关与共享属主修复实现。
//!
//! 本模块同时被 lib（zygisk 注入侧）与 bin（srx_daemon）通过 `#[path]` 引入，
//! 只能依赖双侧都存在的模块：`crate::redirect::policy`、`crate::platform`。

/// 是否允许模块自动调整重定向后端的 owner、group 和 mode。
///
/// 正式构建未设置该环境变量，保持历史行为；实验 CI 构建设置为 `1`，
/// 用于验证只依靠路径重定向、挂载隔离和系统调用策略时的兼容性。
#[inline]
pub(crate) const fn enabled() -> bool {
    !cfg!(srx_no_path_metadata_repair)
}

/// 普通应用 uid 下限（与 AOSP framework 一致）。
pub(crate) const ANDROID_APP_UID_START: i32 = 10000;
/// media_rw 的 uid；属主精确等于该值的条目才视为漂移损伤。
pub(crate) const MEDIA_RW_UID: u32 = 1023;

/// Disable 交接与类别级事件修复单棵树的条目预算（含 lstat）。
#[allow(dead_code)] // quality-allow(lint-suppression): 消费方 events.rs 仅随 daemon bin 再编译，cdylib 构建不可见。
pub(crate) const OWNER_SWEEP_ENTRY_BUDGET: usize = 8192;
/// 挂载应答前浅层修复的条目预算：独立小预算，只求覆盖首波高频故障面
/// （自有目录的顶层与二级子树），冷启动内耗时毫秒级。
pub(crate) const ATTACH_REPAIR_ENTRY_BUDGET: usize = 2048;
/// 挂载应答前浅层修复的最大下钻深度（包根为 0）：`files/Telegram/<目录>`、
/// `files/saves`、`cache/WebView/Crashpad/<子目录>` 均在此范围内。
pub(crate) const ATTACH_REPAIR_MAX_DEPTH: u32 = 4;

/// 自嵌套重定向伪影判定：后端/显示路径里出现
/// `Android/data/<pkg>/sdcard/Android/data/...` 形态的重复。
///
/// 重定向把存储根映射到 `Android/data/<pkg>/sdcard` 之后，应用视图里的同名子树会在
/// 后端再落一层，自相似目录一旦出现就会被监视展开、owner 修复与挂载准备逐层放大
/// （真机实测嵌套 70+ 层直到 ENAMETOOLONG，文件监视线程单核烧满）。这类路径是
/// 映射伪影而不是用户数据，展开与下载判定都应剪掉。
pub(crate) fn is_self_nested_redirect_path(path: &str) -> bool {
    const PRIVATE_PREFIX: &str = "Android/data/";
    const REDIRECT_TAIL: &str = "sdcard/";
    let mut search_from = 0usize;
    while let Some(offset) = path[search_from..].find(PRIVATE_PREFIX) {
        let prefix_start = search_from + offset;
        let after_prefix = &path[prefix_start + PRIVATE_PREFIX.len()..];
        // 形态：<pkg>/sdcard/Android/data/...，<pkg> 为单段包名
        let Some(package_end) = after_prefix.find('/') else {
            break;
        };
        let package = &after_prefix[..package_end];
        if package.is_empty() {
            search_from = prefix_start + PRIVATE_PREFIX.len();
            continue;
        }
        let remainder = &after_prefix[package_end + 1..];
        if let Some(nested) = remainder.strip_prefix(REDIRECT_TAIL)
            && nested.starts_with(PRIVATE_PREFIX)
        {
            return true;
        }
        search_from = prefix_start + PRIVATE_PREFIX.len();
    }
    false
}

/// 把目录树里属主为 media_rw 的条目修回应用 uid，返回实际修正数。
///
/// 只在条目属主精确等于 media_rw 时动手（其余属主一律不动），组与模式位保持
/// 原样（`lchown` 传 -1 保留组）。`budget` 为本轮剩余的**访问条目**预算（含
/// lstat），既限制修复次数也限制干净大树的扫描成本；超支立即返回，剩余部分
/// 留给下轮。`visited` 由调用方累计用于跨包预算。`max_depth` 为相对 `root`
/// 的最大下钻深度（root 自身为 0，`u32::MAX` 表示不限制）：深度达到上限的
/// 目录仍会修复自身，但不再下钻枚举其子项。
pub(crate) fn repair_media_rw_owner_tree(
    root: &str,
    owner_uid: i32,
    package_name: &str,
    budget: usize,
    visited: &mut usize,
    max_depth: u32,
) -> usize {
    let mut repaired = 0usize;
    let mut stack = vec![(root.to_string(), 0u32)];
    while let Some((current, depth)) = stack.pop() {
        if *visited >= budget {
            log::debug!(
                "daemon owner repair scan budget exhausted pkg={} path={}",
                package_name,
                current
            );
            return repaired;
        }
        *visited += 1;
        let Some(c_path) = cstring_path(&current) else {
            continue;
        };
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: c_path 以 NUL 结尾，st 指向可供 lstat 写入的存储空间。
        if unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) } != 0 {
            continue;
        }
        // SAFETY: lstat 已成功返回并完整初始化 stat 值。
        let st = unsafe { st.assume_init() };
        if st.st_uid == MEDIA_RW_UID {
            // SAFETY: c_path 在调用期间保持有效；gid 传 u32::MAX（即 -1）保留组不变。
            let ret = unsafe { libc::lchown(c_path.as_ptr(), owner_uid as u32, u32::MAX) };
            if ret == 0 {
                repaired += 1;
            } else {
                log::warn!(
                    "daemon owner repair failed pkg={} path={} errno={}",
                    package_name,
                    current,
                    crate::platform::errno::last()
                );
            }
        }
        if st.st_mode & libc::S_IFMT as libc::mode_t == libc::S_IFDIR as libc::mode_t {
            if depth >= max_depth {
                continue;
            }
            let Ok(children) = std::fs::read_dir(&current) else {
                continue;
            };
            for child in children.flatten() {
                let child_path = child.path().display().to_string();
                // 重定向目标是模块管理的镜像树（`<pkg>/sdcard`，其中还有自嵌套
                // 复制）：真机实测微信的镜像树足以单独吃满整轮预算，且关闭重定向
                // 后该子树不再被原生视图访问，属主修复对它没有意义。剪掉。
                if current == root && child.file_name().to_string_lossy() == "sdcard" {
                    continue;
                }
                if is_self_nested_redirect_path(&child_path) {
                    continue;
                }
                stack.push((child_path, depth + 1));
            }
        }
    }
    if repaired > 0 {
        log::warn!(
            "daemon owner repair pkg={} uid={} repaired={} root={}",
            package_name,
            owner_uid,
            repaired,
            root
        );
    }
    repaired
}

/// 应用进程首次接入存储视图（新 pid 的挂载应答前）时的浅层属主交接修复。
///
/// 与 Disable 交接修复同源，但面向另一个实测故障窗口（真机 2026-10-17 反馈，
/// A17/SDK37）：应用刚启动时 MediaProvider 代写留下的 media_rw 属主条目尚未被
/// 普查或 daemon 代修兜底，原生 FUSE 对属主非本应用的 Android/data/&lt;pkg&gt; 只给
/// others 位——仅映射模式应用未映射的自有目录探针（Telegram 类）与全量重定向
/// 应用经原生 FUSE 承接的存档读取全部 EACCES。在挂载应答前同步修复，保证应用
/// 首波访问看到的是修复后的属主；只扫浅层（深度 ≤ [`ATTACH_REPAIR_MAX_DEPTH`]）
/// 并使用独立小预算，把冷启动阻塞压到毫秒级，深层残留由 daemon 代修与类别事件兜底。
///
/// daemon fork 与 companion mount 两条挂载路径都必须调用本函数：真机（2026-10-18）
/// 实测 mapping_mode_only 应用的挂载普遍走 companion 路径，只挂 daemon fork 会
/// 完全漏修。
pub(crate) fn repair_app_private_owners_on_attach(package_name: &str, user_id: i32) -> usize {
    if !enabled() || package_name.is_empty() || user_id < 0 {
        return 0;
    }
    if crate::redirect::policy::is_media_intermediate_package(package_name)
        || crate::redirect::policy::is_system_writer_package(package_name)
    {
        return 0;
    }
    let owner_uid = crate::redirect::policy::get_fresh_uid_for_package(package_name);
    if owner_uid < ANDROID_APP_UID_START {
        return 0;
    }
    let mut repaired = 0usize;
    let mut total_visited = 0usize;
    for kind in ["data", "media", "obb"] {
        // 预算必须按 kind 独立：真机 2026-10-18 实证（dada，nagram 存储统计缺失）
        // data 树的 cache 历史积累足以单独吃光共享预算，排在后面的 media 树在
        // 入口即 break，`Android/media/<pkg>/...` 的漂移条目从未被扫到。lstat
        // 单次微秒级，三树独立预算的冷启动阻塞增量可忽略。
        let mut kind_visited = 0usize;
        let root = format!("/data/media/{user_id}/Android/{kind}/{package_name}");
        if !std::path::Path::new(&root).is_dir() {
            continue;
        }
        let kind_repaired = repair_media_rw_owner_tree(
            &root,
            owner_uid,
            package_name,
            ATTACH_REPAIR_ENTRY_BUDGET,
            &mut kind_visited,
            ATTACH_REPAIR_MAX_DEPTH,
        );
        repaired += kind_repaired;
        total_visited += kind_visited;
    }
    log::debug!(
        "attach owner repair done pkg={} visited={} repaired={}",
        package_name,
        total_visited,
        repaired
    );
    if repaired > 0 {
        log::warn!(
            "daemon owner repair on attach pkg={} uid={} entries={}",
            package_name,
            owner_uid,
            repaired
        );
    }
    repaired
}

fn cstring_path(path: &str) -> Option<std::ffi::CString> {
    if path.is_empty() || path.contains('\0') {
        return None;
    }
    std::ffi::CString::new(path).ok()
}

/// 全树修复标记的 TTL：同一应用在本窗口内只做一次 detached 全树扫描，避免
/// 同应用的反复挂载（多 pid）反复整树遍历。QQ/微信这类数万条目的树单次
/// 全扫为秒级，TTL 内的漂移由 OwnerFix 代修与浅层 attach 修复覆盖。
const FULL_SCAN_MARK_TTL_MS: i64 = 60 * 60 * 1000;

fn full_scan_mark_path(package_name: &str, user_id: i32) -> String {
    format!(
        "{}/tmp/owner_fullscan/{}.{}",
        crate::platform::module_paths::MODULE_DIR,
        package_name,
        user_id
    )
}

fn full_scan_mark_fresh(mark_path: &str) -> bool {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let c_path = match std::ffi::CString::new(mark_path) {
        Ok(c_path) => c_path,
        Err(_) => return false,
    };
    // SAFETY: c_path 以 NUL 结尾，st 指向可供 stat 写入的存储空间。
    if unsafe { libc::stat(c_path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: stat 已成功返回并完整初始化 stat 值。
    let st = unsafe { st.assume_init() };
    let Ok(now_ms) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
    else {
        return false;
    };
    let mtime_ms = st.st_mtime * 1000;
    let age = now_ms - mtime_ms;
    (0..FULL_SCAN_MARK_TTL_MS).contains(&age)
}

/// 应用挂载应答完成后启动一次 detached 全树属主修复（double-fork 孙进程）。
///
/// 背景（真机 2026-10-18，QQ 反馈）：attach 期浅层修复受冷启动预算约束
/// （每树 2048 条目、深度 4），QQ 这类 cache/聊天缓存数万条目的大树在预算
/// 内根本扫不到 `files/`、`Tencent/MobileQQ/` 的深层漂移；普查已按需求移除，
/// 大树的全量修复必须由独立机制补上。本函数在挂载应答**之后**由挂载子进程
/// 调用：孙进程经 setsid 脱离，与 daemon/companion/应用完全解耦，不占用任何
/// 挂载链路时间；1 小时去重标记防止同应用多 pid 反复全扫。深层残留另由
/// OwnerFix 请求（MP 实时）与类别事件修复持续覆盖。
pub(crate) fn spawn_detached_full_owner_repair(package_name: &str, user_id: i32) {
    if !enabled() || package_name.is_empty() || user_id < 0 {
        return;
    }
    let mark_path = full_scan_mark_path(package_name, user_id);
    if full_scan_mark_fresh(&mark_path) {
        return;
    }
    crate::logging::prepare_for_fork();
    // SAFETY: fork 前已通过 prepare_for_fork 完成日志句柄处理；中间进程立即
    // 退出，仅用于把孙进程交由 init 收养，避免挂载子进程长时间 wait。
    let middle = unsafe { libc::fork() };
    if middle < 0 {
        return;
    }
    if middle > 0 {
        let mut status = 0;
        // SAFETY: middle 是刚 fork 出的直接子进程，waitpid 回收避免僵尸。
        unsafe { libc::waitpid(middle, &mut status, 0) };
        return;
    }
    // SAFETY: 孙进程 fork 成功后中间进程的唯一职责是立即退出。
    let grandchild = unsafe { libc::fork() };
    if grandchild > 0 {
        unsafe { libc::_exit(0) };
    }
    // SAFETY: setsid 使孙进程脱离调用方会话；失败不影响后续扫描。
    unsafe { libc::setsid() };
    run_full_owner_repair(package_name, user_id, &mark_path);
    unsafe { libc::_exit(0) };
}

fn run_full_owner_repair(package_name: &str, user_id: i32, mark_path: &str) {
    if crate::redirect::policy::is_media_intermediate_package(package_name)
        || crate::redirect::policy::is_system_writer_package(package_name)
    {
        return;
    }
    let owner_uid = crate::redirect::policy::get_fresh_uid_for_package(package_name);
    if owner_uid < ANDROID_APP_UID_START {
        return;
    }
    if let Some(parent) = std::path::Path::new(mark_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(mark_path, b"");
    let mut repaired = 0usize;
    let mut visited = 0usize;
    for kind in ["data", "media", "obb"] {
        let root = format!("/data/media/{user_id}/Android/{kind}/{package_name}");
        if !std::path::Path::new(&root).is_dir() {
            continue;
        }
        repaired += repair_media_rw_owner_tree(
            &root,
            owner_uid,
            package_name,
            usize::MAX,
            &mut visited,
            u32::MAX,
        );
    }
    log::debug!(
        "full owner repair done pkg={} uid={} visited={} repaired={}",
        package_name,
        owner_uid,
        visited,
        repaired
    );
}
