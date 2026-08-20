use pooler_config::compile_yaml;

#[test]
fn upstream_url_boundary_rejects_non_http_and_credential_bearing_urls() {
    let rejected = [
        "file:///etc/passwd",
        "ftp://example.test/provider",
        "http://user:password@example.test/provider",
        "https://user@example.test/provider",
        "http://",
    ];

    for (index, url) in rejected.into_iter().enumerate() {
        let yaml = format!("version: 1\nupstreams:\n  target:\n    url: \"{url}\"\n");
        let error = compile_yaml(format!("phase8-security-{index}.yaml"), &yaml)
            .expect_err("unsafe upstream URL should be rejected");
        let rendered = error.to_string();
        assert!(rendered.contains("upstream"), "{url}: {rendered}");
        assert!(
            !rendered.contains("password"),
            "{url}: secret leaked in {rendered}"
        );
    }
}

#[test]
fn upstream_url_boundary_accepts_explicit_http_and_https_hosts() {
    for (index, url) in ["http://127.0.0.1:8319", "https://provider.example.test/api"]
        .into_iter()
        .enumerate()
    {
        let yaml = format!("version: 1\nupstreams:\n  target:\n    url: \"{url}\"\n");
        compile_yaml(format!("phase8-security-safe-{index}.yaml"), &yaml)
            .expect("valid upstream URL should compile");
    }
}
