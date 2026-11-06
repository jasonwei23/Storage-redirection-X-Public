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
