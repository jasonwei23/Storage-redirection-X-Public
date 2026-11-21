use native_config_fixtures::domain::{PathMapping, mappings_can_use_namespace_bind};

#[test]
fn fixed_storage_mappings_use_namespace_regardless_of_directory_name() {
    for user in [0, 10] {
        let root = format!("/storage/emulated/{user}");
        let mappings = [
            PathMapping::new(format!("{root}/DCIM"), format!("{root}/Download/Reader")),
            PathMapping::new(
                format!("{root}/自建目录/导出"),
                format!("{root}/自建目录/归档"),
            ),
            PathMapping::new(
                format!("{root}/Pictures/Incoming"),
                format!("{root}/自建目录/相册"),
            ),
        ];
        assert!(mappings_can_use_namespace_bind(&mappings, &root));
        let previous = PathMapping::new(format!("{root}/DCIM"), format!("{root}/Pictures/Reader"));
        assert!(mappings_can_use_namespace_bind(&[previous], &root));
    }
}

#[test]
fn private_dynamic_and_overlapping_paths_do_not_select_namespace() {
    let root = "/storage/emulated/0";
    assert!(!mappings_can_use_namespace_bind(&[], root));
    for target in [
        "/storage/emulated/10/Pictures/Reader",
        "/storage/emulated/0/Android/data/org.sample.reader/cache",
        "/storage/emulated/0/android/media/org.sample.reader/cache",
        "/data/user/0/org.sample.reader/cache",
        "/storage/emulated/0/Pictures",
        "/storage/emulated/0/Pictures/*",
        "/storage/emulated/0/Pictures/$app_data_dir",
        "/storage/emulated/0/Pictures/../Android",
        "/storage/emulated/0/Pictures//Reader",
        "/storage/emulated/0/DCIM/Reader",
        "/storage/emulated/0/DCIM",
    ] {
        let mapping = PathMapping::new(format!("{root}/DCIM"), target.into());
        assert!(
            !mappings_can_use_namespace_bind(&[mapping], root),
            "{target}"
        );
    }
    for source in ["DCIM/*", "Android", "dcim", "DCIM/Camera", "pictures"] {
        let first = PathMapping::new(format!("{root}/DCIM"), format!("{root}/Pictures/Reader"));
        let second = PathMapping::new(format!("{root}/{source}"), format!("{root}/Movies/Reader"));
        assert!(
            !mappings_can_use_namespace_bind(&[first, second], root),
            "{source}"
        );
    }
}
