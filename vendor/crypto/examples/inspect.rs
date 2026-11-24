use crypto::CryptoPlugin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("Pass an absolute DLL/SO path")?;
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() {
        return Err("An absolute path is required".into());
    }
    // БЕЗОПАСНОСТЬ: оператор передаёт доверенный плагин с описанным ABI.
    // Загрузка библиотеки исполняет её код инициализации.
    let plugin = unsafe { CryptoPlugin::new(path)? };
    plugin.check_core_api()?;
    println!(
        "Core API available; KDF_TREE: {}",
        plugin.KdfTree_getData.is_ok()
    );
    Ok(())
}
