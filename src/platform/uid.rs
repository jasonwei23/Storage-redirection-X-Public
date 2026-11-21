// Android 多用户 UID 换算的纯函数。
//
// 独立成文件是为了让 native 夹具能以 include! 同源复用：domain.rs 等被夹具
// include 的共享逻辑会调用 `crate::platform::user_id_from_uid`，而夹具的
// platform 模块只 include 子模块、不含 platform.rs 主文件，函数必须落在
// 子模块文件里两边才可见。

/// Android 多用户 UID 偏移：`user_id = uid / 100000`。
pub const ANDROID_USER_ID_OFFSET: i32 = 100000;

/// 由 UID 取 Android 多用户 user_id；负值（如内核回填的 -1）一律视为 user 0。
pub fn user_id_from_uid(uid: i32) -> i32 {
    if uid >= 0 {
        uid / ANDROID_USER_ID_OFFSET
    } else {
        0
    }
}
