mod tests {
    use crypto::CryptoPlugin;

    #[test]
    fn nonexistent_library_returns_an_error() {
        let path = std::env::temp_dir()
            .join(format!("crypto-plugin-missing-{}", std::process::id()))
            .join("missing-library");
        // БЕЗОПАСНОСТЬ: путь не существует, поэтому внешний код не загружается.
        assert!(unsafe { CryptoPlugin::new(path) }.is_err());
    }
}
