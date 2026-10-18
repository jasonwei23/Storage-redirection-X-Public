use super::inotify::{cstring_path, last_errno};
use crate::config::SettingsHub;
use crate::monitor::{infer_public_path_package_name, infer_recent_path_caller_identity};
use crate::platform::{self, paths};
use crate::redirect::policy;
use libc::{
    IN_ATTRIB, IN_CLOSE_WRITE, IN_DELETE, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, mode_t, time, tm,
};
use std::os::unix::fs::MetadataExt;

const LOGCAT_OP_TAG: &str = "FileMonitorOp";
const ANDROID_APP_UID_START: i32 = 10000;
const MEDIA_RW_UID: u32 = 1023;
const MEDIA_RW_GID: u32 = 1023;
const REAL_PUBLIC_DIR_MODE: mode_t = 0o2771;
const REDIRECT_BACKEND_DIR_REQUIRED_MODE: mode_t = 0o2773;
const PRIVATE_CHILD_DIR_REQUIRED_MODE: mode_t = 0o2751;
const PRIVATE_CHILD_FILE_REQUIRED_MODE: mode_t = 0o664;

pub(super) struct MonitorIdentity {
    pub(super) package_name: String,
    pub(super) identify_method: &'static str,
    pub(super) identify_reliability: &'static str,
    pub(super) correlation_id: String,
}

pub(super) struct MonitorEventPaths {
    pub(super) backend_path: String,
    pub(super) display_path: String,
    pub(super) from_path: String,
}

pub(super) fn should_skip_ambiguous_allowed_real_path_event(
    identity: &MonitorIdentity,
    source: &str,
    _display_path: &str,
    watch_package_name: &str,
) -> bool {
    if source != "allowed_real_path" {
        return false;
    }

    if is_media_provider_fallback_identity(identity) {
        return false;
    }

    if identity.identify_method == "public_path_package"
        || is_exact_provider_caller_identity(identity)
    {
        return false;
    }

    if should_keep_system_intermediate_owner_identity(identity, source, watch_package_name) {
        return false;
    }

    if identity.package_name != watch_package_name {
        return true;
    }

    !matches!(identity.identify_method, "owner_uid" | "path_owner")
}

pub(super) fn should_skip_ambiguous_read_only_path_event(
    identity: &MonitorIdentity,
    source: &str,
    watch_package_name: &str,
) -> bool {
    if source != "read_only_path" {
        return false;
    }

    if is_media_provider_fallback_identity(identity) {
        return false;
    }

    if identity.identify_method == "public_path_package"
        || is_exact_provider_caller_identity(identity)
    {
        return false;
    }

    if should_keep_system_intermediate_owner_identity(identity, source, watch_package_name) {
        return false;
    }

    if identity.package_name != watch_package_name {
        return true;
    }

    !matches!(identity.identify_method, "owner_uid" | "path_owner")
}

pub(super) fn should_skip_public_root_event_identity(
    identity: &MonitorIdentity,
    source: &str,
    watch_package_name: &str,
) -> bool {
    if is_media_provider_fallback_identity(identity) {
        return false;
    }

    if identity.identify_method == "public_path_package"
        || is_exact_provider_caller_identity(identity)
    {
        return false;
    }

    if should_keep_system_intermediate_owner_identity(identity, source, watch_package_name) {
        return false;
    }

    source == "public_root"
        && !is_exact_provider_caller_identity(identity)
        && (identity.identify_method != "owner_uid" || identity.package_name != watch_package_name)
}

fn is_exact_provider_caller_identity(identity: &MonitorIdentity) -> bool {
    matches!(
        identity.identify_method,
        "provider_open" | "provider_mkdir" | "saf_provider"
    ) && identity.identify_reliability == "high"
        && !identity.correlation_id.is_empty()
}

pub(super) struct AndroidPrivateOwnerRepairScope {
    pub(super) owner_package: String,
    pub(super) owner_uid: i32,
    pub(super) backend_root: String,
}

pub(super) fn emit_monitor_event(
    identity: &MonitorIdentity,
    paths: &MonitorEventPaths,
    watch_package_name: &str,
    source: &str,
    mask: u32,
    operation_name: &str,
) {
    if identity.package_name.is_empty() || paths.display_path.is_empty() {
        return;
    }

    let event_kind = if operation_name.starts_with("open") {
        "OPEN"
    } else if operation_name.starts_with("delete") {
        "DELETE"
    } else if operation_name.starts_with("rename") {
        "RENAME"
    } else if operation_name.starts_with("attrib") {
        "ATTRIB"
    } else {
        "CREATE"
    };
    let mut line = format!(
        "{}|{}|{}|{}|{}|ret=0|errno=0|identify_method={}|identify_reliability={}|event_role=observation|op={}|source={}|mask=0x{:x}|backend={}",
        build_timestamp(),
        identity.package_name,
        identity.package_name,
        event_kind,
        paths.display_path,
        identity.identify_method,
        identity.identify_reliability,
        operation_name,
        source,
        mask,
        paths.backend_path
    );
    if watch_package_name != identity.package_name {
        line.push_str("|watch_package=");
        line.push_str(watch_package_name);
    }
    if !identity.correlation_id.is_empty() {
        line.push_str("|correlation_id=");
        line.push_str(&identity.correlation_id);
    }
    line.push_str("|observer_package=srx_daemon");
    if !paths.from_path.is_empty() && paths.from_path != paths.display_path {
        line.push_str("|from=");
        line.push_str(&paths.from_path);
    }
    log::info!(target: LOGCAT_OP_TAG, "{}", line);
}

pub(super) fn resolve_monitor_identity(
    watch_package_name: &str,
    display_path: &str,
    backend_path: &str,
    source: &str,
) -> MonitorIdentity {
    let owner = paths::extract_android_private_path_owner(display_path);
    if !owner.is_empty() {
        return MonitorIdentity {
            package_name: owner,
            identify_method: "path_owner",
            identify_reliability: "high",
            correlation_id: String::new(),
        };
    }

    if let Some(identity) = resolve_recent_path_caller_identity(display_path, source) {
        return identity;
    }

    if let Some(package_name) = resolve_package_by_owner_uid(backend_path) {
        if should_prefer_watch_package_for_system_writer_owner(source, &package_name) {
            return watch_package_identity(watch_package_name, "watch_package", "medium");
        }
        return MonitorIdentity {
            package_name,
            identify_method: "owner_uid",
            identify_reliability: "high",
            correlation_id: String::new(),
        };
    }

    let user_id = paths::extract_user_id_from_storage_path(display_path);
    if let Some(package_name) = infer_public_path_package_name(display_path, user_id) {
        return MonitorIdentity {
            package_name,
            identify_method: "public_path_package",
            identify_reliability: "high",
            correlation_id: String::new(),
        };
    }

    if should_use_media_provider_fallback_identity(source, backend_path) {
        return media_provider_fallback_identity();
    }

    watch_package_identity(watch_package_name, "daemon_inotify", "medium")
}

fn resolve_recent_path_caller_identity(
    display_path: &str,
    source: &str,
) -> Option<MonitorIdentity> {
    if !matches!(
        source,
        "allowed_real_path" | "read_only_path" | "public_root"
    ) {
        return None;
    }

    let user_id = paths::extract_user_id_from_storage_path(display_path);
    let identity = infer_recent_path_caller_identity(display_path, user_id)?;
    if identity.confidence != "high"
        || !matches!(
            identity.source,
            "provider_open" | "provider_mkdir" | "saf_provider"
        )
        || identity.package_name.is_empty()
        || policy::is_media_intermediate_package(&identity.package_name)
        || policy::is_system_writer_package(&identity.package_name)
    {
        return None;
    }

    Some(MonitorIdentity {
        package_name: identity.package_name,
        identify_method: identity.source,
        identify_reliability: identity.confidence,
        correlation_id: identity.correlation_id,
    })
}

fn watch_package_identity(
    watch_package_name: &str,
    identify_method: &'static str,
    identify_reliability: &'static str,
) -> MonitorIdentity {
    MonitorIdentity {
        package_name: watch_package_name.to_string(),
        identify_method,
        identify_reliability,
        correlation_id: String::new(),
    }
}

fn resolve_package_by_owner_uid(path: &str) -> Option<String> {
    let uid = std::fs::metadata(path).ok()?.uid() as i32;
    if uid < ANDROID_APP_UID_START {
        return None;
    }

    let mut packages = policy::get_packages_for_uid(uid);
    if packages.is_empty() {
        policy::refresh_shared_uid_cache();
        packages = policy::get_packages_for_uid(uid);
    }
    if packages.len() == 1 {
        packages.into_iter().next()
    } else {
        None
    }
}

fn should_use_media_provider_fallback_identity(source: &str, backend_path: &str) -> bool {
    if !matches!(
        source,
        "allowed_real_path" | "read_only_path" | "public_root"
    ) {
        return false;
    }

    let Ok(metadata) = std::fs::metadata(backend_path) else {
        return false;
    };
    let uid = metadata.uid();
    let gid = metadata.gid();
    uid < ANDROID_APP_UID_START as u32 || gid == MEDIA_RW_GID
}

fn media_provider_fallback_identity() -> MonitorIdentity {
    MonitorIdentity {
        package_name: policy::media_provider_record_package(),
        identify_method: "media_provider_fallback",
        identify_reliability: "fallback",
        correlation_id: String::new(),
    }
}

fn is_media_provider_fallback_identity(identity: &MonitorIdentity) -> bool {
    identity.identify_method == "media_provider_fallback"
        && policy::is_media_provider_package(&identity.package_name)
}

fn should_keep_system_intermediate_owner_identity(
    identity: &MonitorIdentity,
    source: &str,
    watch_package_name: &str,
) -> bool {
    matches!(
        source,
        "allowed_real_path" | "read_only_path" | "public_root"
    ) && identity.package_name != watch_package_name
        && matches!(identity.identify_method, "owner_uid" | "path_owner")
        && !policy::is_media_provider_package(&identity.package_name)
        && policy::is_media_intermediate_package(&identity.package_name)
}

pub(super) fn should_prefer_watch_package_for_system_writer_owner(
    source: &str,
    owner_package: &str,
) -> bool {
    matches!(source, "path_mapping" | "sandbox_path" | "redirect_root")
        && (policy::is_system_writer_package(owner_package)
            || policy::is_media_intermediate_package(owner_package))
}

pub(super) fn repair_monitored_backend_owner(
    source: &str,
    watch_package_name: &str,
    display_path: &str,
    backend_path: &str,
) {
    if !crate::metadata_repair::enabled() {
        return;
    }
    if source == "private_category_owner" {
        repair_private_category_owner(backend_path);
        return;
    }
    if source == "public_owner" {
        repair_public_directory_owner(display_path, backend_path);
        return;
    }
    let scope = if source == "redirect_root" {
        redirect_backend_owner_repair_scope(watch_package_name)
    } else {
        android_private_owner_repair_scope(display_path)
    };
    let Some(scope) = scope else {
        return;
    };
    repair_backend_owner_in_scope(&scope, backend_path);
}

fn repair_public_directory_owner(display_path: &str, backend_path: &str) {
    let normalized = paths::normalize(display_path);
    let user_id = paths::extract_user_id_from_storage_path(&normalized);
    if user_id < 0 {
        return;
    }
    let storage_root = paths::storage_user_root_for_user(user_id);
    let Some(relative) = paths::relative_child_path(&normalized, &storage_root) else {
        return;
    };
    if relative.is_empty() || is_android_app_private_relative_path(relative) {
        return;
    }
    let expected_backend = paths::storage_to_data_media_path(&normalized);
    if !paths::eq_ignore_case(&expected_backend, backend_path) {
        return;
    }

    let Some(c_path) = cstring_path(backend_path) else {
        return;
    };
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: c_path 以 NUL 结尾，st 指向可供 lstat 写入的存储空间。
    if unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return;
    }
    // SAFETY: lstat 已成功返回并完整初始化 stat 值。
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT as mode_t != libc::S_IFDIR as mode_t {
        return;
    }

    if st.st_uid != MEDIA_RW_UID || st.st_gid != MEDIA_RW_GID {
        // SAFETY: c_path 在调用期间保持有效，并指向已验证的公共目录。
        let ret = unsafe { libc::lchown(c_path.as_ptr(), MEDIA_RW_UID, MEDIA_RW_GID) };
        if ret != 0 {
            log::warn!(
                "daemon public owner fix failed path={} errno={}",
                backend_path,
                last_errno()
            );
            return;
        }
        log::info!("daemon public owner fix path={}", backend_path);
    }

    let current_mode = st.st_mode & 0o7777;
    if current_mode != REAL_PUBLIC_DIR_MODE {
        // SAFETY: c_path 在调用期间保持有效，并指向已验证的公共目录。
        let ret = unsafe { libc::chmod(c_path.as_ptr(), REAL_PUBLIC_DIR_MODE) };
        if ret != 0 {
            log::warn!(
                "daemon public chmod fix failed path={} errno={}",
                backend_path,
                last_errno()
            );
        }
    }
}

fn is_android_app_private_relative_path(relative: &str) -> bool {
    let mut parts = relative.split('/').filter(|part| !part.is_empty());
    parts.next() == Some("Android") && matches!(parts.next(), Some("data" | "media" | "obb"))
}

fn repair_backend_owner_in_scope(scope: &AndroidPrivateOwnerRepairScope, backend_path: &str) {
    if !path_is_same_or_child(backend_path, &scope.backend_root) {
        return;
    }

    let mut pending = Vec::new();
    let mut current = backend_path.to_string();
    loop {
        if !path_is_same_or_child(&current, &scope.backend_root) {
            break;
        }
        pending.push(current.clone());
        if current == scope.backend_root {
            break;
        }
        let parent = raw_parent(&current);
        if parent.is_empty() || parent == current {
            break;
        }
        current = parent;
    }

    for path in pending.into_iter().rev() {
        chown_android_private_path_if_needed(
            &path,
            scope.owner_uid,
            &scope.owner_package,
            &scope.backend_root,
        );
    }
}

fn redirect_backend_owner_repair_scope(
    package_name: &str,
) -> Option<AndroidPrivateOwnerRepairScope> {
    if package_name.is_empty()
        || policy::is_media_intermediate_package(package_name)
        || policy::is_system_writer_package(package_name)
    {
        return None;
    }

    let owner_uid = resolve_android_private_owner_uid(package_name);
    if owner_uid < ANDROID_APP_UID_START {
        return None;
    }
    let user_id = platform::user_id_from_uid(owner_uid);
    if user_id < 0 || !SettingsHub::instance().should_redirect(package_name, owner_uid) {
        return None;
    }

    let storage_root = paths::default_redirect_target(package_name, user_id);
    Some(AndroidPrivateOwnerRepairScope {
        owner_package: package_name.to_string(),
        owner_uid,
        backend_root: paths::storage_to_data_media_path(&storage_root),
    })
}

pub(super) fn android_private_owner_repair_scope(
    display_path: &str,
) -> Option<AndroidPrivateOwnerRepairScope> {
    let normalized = paths::normalize(display_path);
    let owner_package = paths::extract_android_private_path_owner(&normalized);
    if owner_package.is_empty()
        || policy::is_media_intermediate_package(&owner_package)
        || policy::is_system_writer_package(&owner_package)
    {
        return None;
    }

    let user_id = paths::extract_user_id_from_storage_path(&normalized);
    if user_id < 0 {
        return None;
    }

    let owner_uid = resolve_android_private_owner_uid(&owner_package);
    if owner_uid < ANDROID_APP_UID_START || platform::user_id_from_uid(owner_uid) != user_id {
        return None;
    }

    if !SettingsHub::instance().should_redirect(&owner_package, owner_uid) {
        return None;
    }

    let backend_root =
        paths::android_private_data_media_root(&normalized, &owner_package, user_id)?;
    Some(AndroidPrivateOwnerRepairScope {
        owner_package,
        owner_uid,
        backend_root,
    })
}

fn resolve_android_private_owner_uid(package_name: &str) -> i32 {
    policy::get_fresh_uid_for_package(package_name)
}

fn chown_android_private_path_if_needed(
    path: &str,
    owner_uid: i32,
    owner_package: &str,
    private_root: &str,
) {
    // private_root 是 MediaProvider 创建并维护的应用私有根。它的 owner/mode 可能随
    // Android 版本、厂商实现或 FUSE 层不同，守护进程不能在每次事件中把根目录强制改成
    // 应用 UID/固定模式；根目录被改写后，应用会表现为必须额外配置允许路径才能访问。
    // 子目录和文件仍保留现有的按需修复逻辑，处理重定向链路确实新建出的条目。
    if paths::eq_ignore_case(path, private_root) {
        return;
    }
    let Some(c_path) = cstring_path(path) else {
        return;
    };

    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let stat_ret = unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) };
    if stat_ret != 0 {
        return;
    }
    let st = unsafe { st.assume_init() };
    if st.st_uid == owner_uid as u32 && st.st_gid == MEDIA_RW_GID {
        chmod_android_private_path_if_needed(&c_path, path, &st, owner_package, private_root);
        return;
    }

    let ret = unsafe { libc::lchown(c_path.as_ptr(), owner_uid as u32, MEDIA_RW_GID) };
    if ret == 0 {
        chmod_android_private_path_if_needed(&c_path, path, &st, owner_package, private_root);
        log::info!(
            "daemon private owner fix path={} owner={} uid={}",
            path,
            owner_package,
            owner_uid
        );
        return;
    }

    let error_no = last_errno();
    if error_no != libc::ENOENT {
        log::warn!(
            "daemon private owner fix failed path={} owner={} uid={} errno={}",
            path,
            owner_package,
            owner_uid,
            error_no
        );
    }
}

fn chmod_android_private_path_if_needed(
    c_path: &std::ffi::CString,
    path: &str,
    st: &libc::stat,
    owner_package: &str,
    private_root: &str,
) {
    let file_type = st.st_mode & libc::S_IFMT as mode_t;
    if should_skip_android_private_cache_file_chmod(path, private_root, file_type) {
        return;
    }
    let required_mode = match file_type {
        value if value == libc::S_IFDIR as mode_t => android_private_dir_required_mode(path),
        value if value == libc::S_IFREG as mode_t => PRIVATE_CHILD_FILE_REQUIRED_MODE,
        _ => return,
    };
    let current_mode = st.st_mode & 0o7777;
    if current_mode & required_mode == required_mode {
        return;
    }

    let fixed_mode = current_mode | required_mode;
    let ret = unsafe { libc::chmod(c_path.as_ptr(), fixed_mode) };
    if ret == 0 {
        log::info!(
            "daemon private chmod fix path={} owner={} mode={:o}",
            path,
            owner_package,
            fixed_mode
        );
        return;
    }

    let error_no = last_errno();
    if error_no != libc::ENOENT {
        log::warn!(
            "daemon private chmod fix failed path={} owner={} mode={:o} errno={}",
            path,
            owner_package,
            fixed_mode,
            error_no
        );
    }
}

fn android_private_dir_required_mode(path: &str) -> mode_t {
    if paths::is_default_redirect_backend_path(path) {
        REDIRECT_BACKEND_DIR_REQUIRED_MODE
    } else {
        PRIVATE_CHILD_DIR_REQUIRED_MODE
    }
}

fn should_skip_android_private_cache_file_chmod(
    path: &str,
    private_root: &str,
    file_type: mode_t,
) -> bool {
    if file_type != libc::S_IFREG as mode_t || paths::is_sqlite_database_or_sidecar_path(path) {
        return false;
    }

    let Some(relative) = paths::child_suffix(path, private_root) else {
        return false;
    };
    let relative = relative.trim_start_matches('/');
    relative == "cache" || relative.starts_with("cache/")
}

pub(super) fn path_is_same_or_child(path: &str, root: &str) -> bool {
    paths::is_same_or_child(path, root)
}

/// 属主清扫的最小间隔。属主异常是历史损伤（旧版本在重定向开启期把应用私有子树
/// chown 成 media_rw，或系统代写留下的陈旧状态），低频修复即可，不值得更高频率。
const OWNER_SWEEP_INTERVAL_MS: i64 = 30 * 60 * 1000;
/// 单轮最多**访问**的条目数（含 lstat）。既封顶修复次数也封顶干净大树的扫描
/// 成本：预算耗尽立即返回，剩余部分等下一个间隔自动续扫，保证单轮对 daemon
/// 主循环的阻塞有界。
const OWNER_SWEEP_ENTRY_BUDGET: usize = crate::metadata_repair::OWNER_SWEEP_ENTRY_BUDGET;
/// 上次属主清扫的单调时刻；0 表示从未跑过（启动后第一个间隔点即执行）。
static LAST_OWNER_SWEEP_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
/// 清扫轮转游标：keys 向量中的下一个起始下标（预算耗尽时停在该包，下一轮续扫）。
static SWEEP_CURSOR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 周期性清扫 `/data/media/*/Android/{data,media,obb}/<pkg>` 的 media_rw 属主异常。
///
/// 背景（真机 2026-10-16 实证）：应用私有子树的正确属主是应用 uid——顶层目录组为
/// ext_data_rw、内容目录组为 media_rw 都属正常形态，唯独**属主**不能是 media_rw：
/// 原生 FUSE 对属主非本应用的 Android/data/<pkg> 只给 others 位（通常 --x），
/// 应用读写全部被拒，Unity 类应用表现为存档不可读写并回退内部存储。现有的
/// [`repair_monitored_backend_owner`] 只覆盖 `should_redirect` 通过的受监视应用
/// （且依赖 inotify 事件触发），关闭重定向/未配置的应用无人看护、无人修复。
/// 这里对存储后端做低频全量普查：只把「属主 == media_rw」的异常条目修回应用
/// uid（`lchown` 仅改属主，组与模式位保持原样）；应用未安装或无法解析 uid 的
/// 陈旧目录一律不碰。
pub(crate) fn maybe_sweep_android_data_owners() {
    if !crate::metadata_repair::enabled() {
        return;
    }
    let now = crate::platform::paths::monotonic_ms();
    let last = LAST_OWNER_SWEEP_MS.load(std::sync::atomic::Ordering::Relaxed);
    // 触发文件用于现场取证：创建即立即执行一次（无论间隔），跑完自动删除。
    let forced =
        std::path::Path::new("/data/adb/modules/storage.redirect.x/.owner_sweep_now").exists();
    if !forced && last != 0 && now - last < OWNER_SWEEP_INTERVAL_MS {
        return;
    }
    LAST_OWNER_SWEEP_MS.store(now, std::sync::atomic::Ordering::Relaxed);
    if forced {
        let _ = std::fs::remove_file("/data/adb/modules/storage.redirect.x/.owner_sweep_now");
    }

    let mut repaired = 0usize;
    let mut visited = 0usize;
    let mut scanned = 0usize;
    // 先收集再按固定顺序轮转：read_dir 顺序不稳定，且单棵大树可能吃满预算，
    // 固定从头开始会让排序靠后的包永远轮不到（真机实测微信镜像树现象）。
    // 游标记录本轮推进到的位置，下一轮从这里继续，保证所有包轮转覆盖。
    let mut keys: Vec<String> = Vec::new();
    let Ok(user_entries) = std::fs::read_dir("/data/media") else {
        return;
    };
    let mut user_paths: Vec<String> = user_entries
        .flatten()
        .map(|entry| entry.path().display().to_string())
        .collect();
    user_paths.sort();
    for user_path in user_paths {
        for kind in ["data", "media", "obb"] {
            let category_dir = format!("{user_path}/Android/{kind}");
            let Ok(packages) = std::fs::read_dir(&category_dir) else {
                continue;
            };
            let mut package_paths: Vec<String> = packages
                .flatten()
                .map(|entry| entry.path().display().to_string())
                .collect();
            package_paths.sort();
            for package_path in package_paths {
                keys.push(format!("{kind}|{package_path}"));
            }
        }
    }
    if keys.is_empty() {
        return;
    }
    let start = SWEEP_CURSOR.load(std::sync::atomic::Ordering::Relaxed) % keys.len();
    let mut stop = start;
    for offset in 0..keys.len() {
        let index = (start + offset) % keys.len();
        let key = &keys[index];
        let Some((_, package_path)) = key.split_once('|') else {
            continue;
        };
        scanned += 1;
        let Ok(meta) = std::fs::symlink_metadata(package_path) else {
            continue;
        };
        // 深层损伤（如 files/saves 属主异常而包目录顶层正常）是实测的主要
        // 形态，顶层属主正常不代表子树干净——每个包目录都下钻扫描，由
        // repair_media_rw_owner_tree 内部只修属主精确等于 media_rw 的条目。
        if !meta.is_dir() {
            continue;
        }
        let package_name = package_path.rsplit('/').next().unwrap_or_default();
        if policy::is_media_intermediate_package(package_name)
            || policy::is_system_writer_package(package_name)
        {
            continue;
        }
        let owner_uid = policy::get_fresh_uid_for_package(package_name);
        if owner_uid < ANDROID_APP_UID_START {
            continue;
        }
        if visited >= OWNER_SWEEP_ENTRY_BUDGET {
            log::warn!(
                "daemon owner sweep budget exhausted visited={} repaired={} scanned={}",
                visited,
                repaired,
                scanned
            );
            stop = index;
            break;
        }
        repaired += crate::metadata_repair::repair_media_rw_owner_tree(
            package_path,
            owner_uid,
            package_name,
            OWNER_SWEEP_ENTRY_BUDGET,
            &mut visited,
            u32::MAX,
        );
        stop = (index + 1) % keys.len();
    }
    SWEEP_CURSOR.store(stop, std::sync::atomic::Ordering::Relaxed);
    // 无条件记录汇总：这是低频操作（30 分钟一次或触发文件），留一条执行证据
    // 便于现场判断普查是否真的跑过、扫到了哪里。
    log::warn!(
        "daemon owner sweep done visited={} repaired={} scanned={} cursor={}",
        visited,
        repaired,
        scanned,
        stop
    );
}

/// 应用退出重定向（Disable）时的属主交接修复。
///
/// 关闭重定向意味着模块要把存储视图交还原生 FUSE：原生模型要求应用私有子树
/// 属主是应用 uid，而重定向开启期可能留下属主为 media_rw 的条目（系统代写、
/// 旧版本损伤）。交还前就地修干净，应用关掉重定向的瞬间即可正常读写存档，
/// 不必等类别 watch 事件或低频普查。预算与普查共用，超支部分由后续机制兜底。
pub(crate) fn repair_app_private_owners(package_name: &str, user_id: i32) -> usize {
    if !crate::metadata_repair::enabled() || package_name.is_empty() || user_id < 0 {
        return 0;
    }
    if policy::is_media_intermediate_package(package_name)
        || policy::is_system_writer_package(package_name)
    {
        return 0;
    }
    let owner_uid = policy::get_fresh_uid_for_package(package_name);
    if owner_uid < ANDROID_APP_UID_START {
        return 0;
    }
    let mut repaired = 0usize;
    let mut visited = 0usize;
    for kind in ["data", "media", "obb"] {
        if visited >= OWNER_SWEEP_ENTRY_BUDGET {
            break;
        }
        let root = format!("/data/media/{user_id}/Android/{kind}/{package_name}");
        if !std::path::Path::new(&root).is_dir() {
            continue;
        }
        repaired += crate::metadata_repair::repair_media_rw_owner_tree(
            &root,
            owner_uid,
            package_name,
            OWNER_SWEEP_ENTRY_BUDGET,
            &mut visited,
            u32::MAX,
        );
    }
    if repaired > 0 {
        log::warn!(
            "daemon disable owner repair pkg={} uid={} entries={}",
            package_name,
            owner_uid,
            repaired
        );
    }
    repaired
}

/// 类别级私有属主事件的修复入口：backend_path 形如
/// `/data/media/<user>/Android/<data|media|obb>/<pkg>`。
///
/// 只在包目录存在、是目录且属主精确等于 media_rw 时修复（这正是损坏形态：
/// 正常状态下包目录属主是应用 uid，组才是 media_rw/ext_data_rw）。应用未安装
/// 或 uid 无法解析的陈旧目录不动。watch 登记时的存量检查与运行期 IN_ATTRIB /
/// IN_CREATE / IN_MOVED_TO 事件都走这里。
fn repair_private_category_owner(backend_path: &str) {
    let mut parts = backend_path.split('/').filter(|part| !part.is_empty());
    // 形状校验：…/Android/<kind>/<pkg>，防止其它来源的事件误入。
    let Some(package_name) = parts.next_back() else {
        return;
    };
    let Some(kind) = parts.next_back() else {
        return;
    };
    if !matches!(kind, "data" | "media" | "obb") || parts.next_back() != Some("Android") {
        return;
    }
    // 倒数第四段必须是用户号（纯数字）：把类别目录自身（…/Android/<kind>）挡在外面。
    let Some(user_segment) = parts.next_back() else {
        return;
    };
    if user_segment.is_empty() || !user_segment.bytes().all(|byte| byte.is_ascii_digit()) {
        return;
    }
    if package_name.is_empty() || package_name.contains('/') {
        return;
    }
    let Ok(meta) = std::fs::symlink_metadata(backend_path) else {
        return;
    };
    if !meta.is_dir() || meta.uid() != MEDIA_RW_UID {
        return;
    }
    if policy::is_media_intermediate_package(package_name)
        || policy::is_system_writer_package(package_name)
    {
        return;
    }
    let owner_uid = policy::get_fresh_uid_for_package(package_name);
    if owner_uid < ANDROID_APP_UID_START {
        return;
    }
    let mut visited = 0usize;
    crate::metadata_repair::repair_media_rw_owner_tree(
        backend_path,
        owner_uid,
        package_name,
        OWNER_SWEEP_ENTRY_BUDGET,
        &mut visited,
        u32::MAX,
    );
}

// 把目录树里属主为 media_rw 的条目修回应用 uid 的实现已下沉到
// crate::metadata_repair::repair_media_rw_owner_tree（lib/bin 共享，
// companion mount 路径也需要调用）；本侧调用统一转发。
fn raw_parent(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return path.to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(pos) => trimmed[..pos].to_string(),
        None => String::new(),
    }
}

pub(super) fn should_filter_display_path(path: &str, operation_name: &str) -> bool {
    paths::is_filtered_media_provider_path(path)
        || SettingsHub::instance().should_filter_monitor_record(path, operation_name)
}

pub(super) fn monitor_operation_from_mask(mask: u32) -> &'static str {
    if (mask & (IN_MOVED_TO | IN_MOVED_FROM)) != 0 {
        "rename"
    } else if (mask & IN_DELETE) != 0 {
        "delete"
    } else if (mask & IN_ATTRIB) != 0 {
        "attrib"
    } else if (mask & (IN_MODIFY | IN_CLOSE_WRITE)) != 0 {
        "open:write"
    } else {
        "inotify"
    }
}

fn build_timestamp() -> String {
    let mut now: libc::time_t = 0;
    unsafe { time(&mut now as *mut _) };

    let mut tm_value: tm = unsafe { std::mem::zeroed() };
    let tm_ptr = unsafe { libc::localtime_r(&now as *const _, &mut tm_value as *mut _) };
    if tm_ptr.is_null() {
        return String::new();
    }

    let mut buffer = [0u8; 32];
    let format = b"%Y-%m-%d %H:%M:%S\0";
    let written = unsafe {
        libc::strftime(
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            format.as_ptr() as *const _,
            &tm_value as *const _,
        )
    };
    if written == 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buffer[..written]).to_string()
}
