// 将真实策略函数编译进此夹具；其余类型仅提供请求输入，不复制门控逻辑。
struct PathMapping {
    request_path: String,
    final_path: String,
}
enum StorageBackendMode {
    Auto,
}

mod platform {
    pub const ANDROID_USER_ID_OFFSET: i32 = 100000;
    pub fn user_id_from_uid(uid: i32) -> i32 {
        uid / 100000
    }
}
mod paths {
    pub fn contains_wildcards(path: &str) -> bool {
        path.contains('*') || path.contains('?')
    }
    pub fn default_redirect_target(package: &str, user: i32) -> String {
        format!("/storage/emulated/{user}/Android/data/{package}/sdcard")
    }
}

include!("cache_policy.rs");

struct Request {
    uid: i32,
    target: String,
    monitor: bool,
    monitor_only: bool,
    allow: Vec<String>,
    exclude: Vec<String>,
    sandbox: Vec<String>,
    read_only: Vec<String>,
    mappings: Vec<PathMapping>,
}
impl Request {
    fn new() -> Self {
        Self {
            uid: 10355,
            target: paths::default_redirect_target("org.sample.reader", 0),
            monitor: false,
            monitor_only: false,
            allow: vec![],
            exclude: vec![],
            sandbox: vec![],
            read_only: vec![],
            mappings: vec![PathMapping {
                request_path: "DCIM".into(),
                final_path: "Pictures/Reader".into(),
            }],
        }
    }
}
impl MountRequestFields for Request {
    fn package_name(&self) -> &str {
        "org.sample.reader"
    }
    fn pid(&self) -> i32 {
        123
    }
    fn uid(&self) -> i32 {
        self.uid
    }
    fn app_data_dir(&self) -> &str {
        "/data/user/0/org.sample.reader"
    }
    fn redirect_target(&self) -> &str {
        &self.target
    }
    fn is_file_monitor_enabled(&self) -> bool {
        self.monitor
    }
    fn storage_backend_mode(&self) -> StorageBackendMode {
        StorageBackendMode::Auto
    }
    fn allowed_real_paths(&self) -> &[String] {
        &self.allow
    }
    fn excluded_real_paths(&self) -> &[String] {
        &self.exclude
    }
    fn sandboxed_paths(&self) -> &[String] {
        &self.sandbox
    }
    fn read_only_paths(&self) -> &[String] {
        &self.read_only
    }
    fn path_mappings(&self) -> &[PathMapping] {
        &self.mappings
    }
    fn is_mapping_mode_only(&self) -> bool {
        false
    }
    fn is_monitor_only(&self) -> bool {
        self.monitor_only
    }
}

fn main() {
    assert!(native_cache_restore_allowed(&Request::new()));
    let mut request = Request::new();
    request.mappings.clear();
    assert!(native_cache_restore_allowed(&request));
    request.uid = 1010355;
    request.target = paths::default_redirect_target(request.package_name(), 10);
    assert!(native_cache_restore_allowed(&request));

    for category in 0..4 {
        let mut request = Request::new();
        let rules = match category {
            0 => &mut request.allow,
            1 => &mut request.exclude,
            2 => &mut request.sandbox,
            _ => &mut request.read_only,
        };
        rules.push("Android/data/org.sample.reader/cache".into());
        assert!(!native_cache_restore_allowed(&request));
    }
    let mut request = Request::new();
    request.monitor = true;
    assert!(!native_cache_restore_allowed(&request));
    request.monitor = false;
    request.monitor_only = true;
    assert!(!native_cache_restore_allowed(&request));
    request.monitor_only = false;
    request.uid = 999;
    assert!(!native_cache_restore_allowed(&request));
    request.uid = 1000999;
    assert!(!native_cache_restore_allowed(&request));

    for target in [
        "/storage/emulated/0",
        "/storage/emulated/0/Android/data/org.sample.reader/cache",
    ] {
        let mut request = Request::new();
        request.target = target.into();
        assert!(!native_cache_restore_allowed(&request));
    }
    for path in [
        "Android/data/org.sample.reader/cache",
        "/storage/emulated/0/DCIM",
        "DCIM/*",
        "DCIM/../Android/data",
        "DCIM/$app_data_dir",
        "DCIM//cache",
        "DCIM/./cache",
        "",
    ] {
        let mut request = Request::new();
        request.mappings[0].request_path = path.into();
        assert!(!native_cache_restore_allowed(&request), "请求路径 {path}");
        request.mappings[0].request_path = "DCIM".into();
        request.mappings[0].final_path = path.into();
        assert!(!native_cache_restore_allowed(&request), "目标路径 {path}");
    }
}
