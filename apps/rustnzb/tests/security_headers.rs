//! Browser-facing security headers and CORS policy on the HTTP router.
//!
//! The web UI keeps its bearer token in `localStorage`, so a Content Security
//! Policy is the defence in depth against script injection, and nothing on
//! this server needs to be readable cross-origin by an arbitrary site. *arr
//! clients talk to the SABnzbd API server-to-server, where CORS does not
//! apply, so they must keep working whatever the CORS policy is.

use std::sync::Arc;

use arc_swap::ArcSwap;
use nzb_web::auth::{CredentialStore, TokenStore};
use nzb_web::nzb_core::config::AppConfig;
use nzb_web::nzb_core::db::Database;
use nzb_web::{AppState, LogBuffer, QueueManager};
use rustnzb::server::build_router;

const SAB_KEY: &str = "security-headers-test-key";

async fn start(
    cors_allowed_origins: Vec<String>,
) -> (String, tempfile::TempDir, tokio::task::JoinHandle<()>) {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let mut config = AppConfig::default();
    config.general.api_key = Some(SAB_KEY.into());
    config.general.cors_allowed_origins = cors_allowed_origins;

    let log_buffer = LogBuffer::new();
    let manager = QueueManager::new(
        Vec::new(),
        Database::open_memory().expect("open database"),
        tempdir.path().join("incomplete"),
        tempdir.path().join("complete"),
        log_buffer.clone(),
        config.general.max_active_downloads,
        config.categories.clone(),
        config.general.min_free_space_bytes,
        config.general.speed_limit_bps,
        false,
        config.general.max_nested_archive_depth,
        config.general.abort_hopeless,
        config.general.early_failure_check,
        config.general.required_completion_pct,
        config.general.article_timeout_secs,
    );
    let state = Arc::new(AppState::new(
        Arc::new(ArcSwap::from_pointee(config)),
        tempdir.path().join("config.toml"),
        manager,
        log_buffer,
        Arc::new(TokenStore::new()),
        Arc::new(CredentialStore::new(tempdir.path().to_path_buf())),
    ));
    let router = build_router(state);
    #[cfg(feature = "webdav")]
    let router = router.layer(axum::Extension(None::<Arc<rustnzb::dav::DavHandle>>));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve test app");
    });
    (base_url, tempdir, handle)
}

fn header<'a>(resp: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn assert_security_headers(resp: &reqwest::Response, path: &str) {
    let csp = header(resp, "content-security-policy")
        .unwrap_or_else(|| panic!("{path}: missing Content-Security-Policy"));
    for directive in [
        "default-src 'self'",
        "script-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "font-src 'self' https://fonts.gstatic.com",
    ] {
        assert!(
            csp.contains(directive),
            "{path}: CSP {csp:?} lacks {directive:?}"
        );
    }
    let script_src = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src"))
        .expect("script-src directive");
    assert!(
        !script_src.contains("unsafe"),
        "{path}: script-src must not allow unsafe sources: {script_src:?}"
    );
    assert_eq!(header(resp, "x-frame-options"), Some("DENY"), "{path}");
    assert_eq!(
        header(resp, "x-content-type-options"),
        Some("nosniff"),
        "{path}"
    );
    assert_eq!(
        header(resp, "referrer-policy"),
        Some("no-referrer"),
        "{path}"
    );
}

#[tokio::test]
async fn every_surface_sends_security_headers() {
    let (base, _tmp, handle) = start(Vec::new()).await;
    let client = reqwest::Client::new();

    for path in [
        "/".to_string(),
        "/queue".to_string(),
        "/api/health".to_string(),
        "/api/status".to_string(), // 401 without a token: errors carry them too
        format!("/sabnzbd/api?mode=version&apikey={SAB_KEY}"),
        "/swagger-ui/".to_string(),
    ] {
        let resp = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .expect("request");
        assert_security_headers(&resp, &path);
    }
    handle.abort();
}

#[tokio::test]
async fn cross_origin_reads_are_refused_by_default() {
    let (base, _tmp, handle) = start(Vec::new()).await;
    let client = reqwest::Client::new();

    for path in [
        format!("/sabnzbd/api?mode=queue&output=json&apikey={SAB_KEY}"),
        format!("/api?mode=queue&output=json&apikey={SAB_KEY}"),
        "/api/auth/status".to_string(),
        "/api/status".to_string(),
    ] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("Origin", "https://evil.example")
            .send()
            .await
            .expect("request");
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            None,
            "{path}: an arbitrary site must not be granted cross-origin reads"
        );

        let preflight = client
            .request(reqwest::Method::OPTIONS, format!("{base}{path}"))
            .header("Origin", "https://evil.example")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "authorization")
            .send()
            .await
            .expect("preflight");
        assert_eq!(
            header(&preflight, "access-control-allow-origin"),
            None,
            "{path}: preflight from an arbitrary site must not be approved"
        );
    }
    handle.abort();
}

#[tokio::test]
async fn sab_clients_without_an_origin_are_unaffected() {
    // *arr applications and mobile clients call the SAB API server-to-server:
    // no Origin header, so the CORS policy must not change their responses.
    let (base, _tmp, handle) = start(Vec::new()).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "{base}/sabnzbd/api?mode=version&output=json&apikey={SAB_KEY}"
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body.get("version").is_some(), "unexpected body {body}");
    handle.abort();
}

#[tokio::test]
async fn configured_origins_are_allowed_and_others_are_not() {
    let (base, _tmp, handle) = start(vec!["https://dash.example".into()]).await;
    let client = reqwest::Client::new();
    let url = format!("{base}/api/auth/status");

    let allowed = client
        .get(&url)
        .header("Origin", "https://dash.example")
        .send()
        .await
        .expect("request");
    assert_eq!(
        header(&allowed, "access-control-allow-origin"),
        Some("https://dash.example")
    );

    let preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", "https://dash.example")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization,content-type",
        )
        .send()
        .await
        .expect("preflight");
    assert_eq!(
        header(&preflight, "access-control-allow-origin"),
        Some("https://dash.example")
    );
    let allow_headers = header(&preflight, "access-control-allow-headers")
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        allow_headers.contains("authorization"),
        "preflight must allow the Authorization header: {allow_headers:?}"
    );

    let refused = client
        .get(&url)
        .header("Origin", "https://evil.example")
        .send()
        .await
        .expect("request");
    assert_eq!(header(&refused, "access-control-allow-origin"), None);
    handle.abort();
}

#[tokio::test]
async fn health_probe_stays_readable_cross_origin() {
    // The desktop shell's splash page polls /api/health from its own origin
    // before navigating to the UI; the endpoint carries no data.
    let (base, _tmp, handle) = start(Vec::new()).await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/health"))
        .header("Origin", "tauri://localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "access-control-allow-origin"), Some("*"));
    handle.abort();
}
