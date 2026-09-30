fn main() {
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("phonegate.manifest"));
    // Only these app commands exist; each needs an explicit capability grant.
    let app = tauri_build::AppManifest::new().commands(&["agent", "qr_svg", "apk_info", "reveal_apk"]);
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows).app_manifest(app))
        .expect("failed to run tauri-build");
}
