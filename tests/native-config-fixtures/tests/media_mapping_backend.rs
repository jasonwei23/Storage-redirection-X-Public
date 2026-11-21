use native_config_fixtures::domain::{PathMapping, is_single_concrete_media_mapping};

#[test]
fn normalized_cross_collection_mapping_uses_the_current_user_root() {
    for user in [0, 10] {
        let root = format!("/storage/emulated/{user}");
        let mapping = PathMapping::new(format!("{root}/DCIM"), format!("{root}/Pictures/Reader"));
        assert!(is_single_concrete_media_mapping(&[mapping], &root));
    }
}

#[test]
fn private_dynamic_and_overlapping_paths_do_not_select_namespace() {
    let root = "/storage/emulated/0";
    for target in [
        "/storage/emulated/10/Pictures/Reader",
        "/storage/emulated/0/Android/data/org.sample.reader/cache",
        "/storage/emulated/0/Pictures",
        "/storage/emulated/0/Pictures/*",
        "/storage/emulated/0/Pictures/$app_data_dir",
        "/storage/emulated/0/Pictures/../Android",
        "/storage/emulated/0/Pictures//Reader",
        "/storage/emulated/0/DCIM/Reader",
    ] {
        let mapping = PathMapping::new(format!("{root}/DCIM"), target.into());
        assert!(
            !is_single_concrete_media_mapping(&[mapping], root),
            "{target}"
        );
    }
    let first = PathMapping::new(format!("{root}/DCIM"), format!("{root}/Pictures/Reader"));
    let second = PathMapping::new(format!("{root}/Pictures"), format!("{root}/Movies/Reader"));
    assert!(!is_single_concrete_media_mapping(&[first, second], root));
}
