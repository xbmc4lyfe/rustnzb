//! Deterministic in-process API contract coverage for authentication,
//! validation, response shape, and configuration persistence.

mod support;

use std::sync::Arc;

use arc_swap::ArcSwap;
use nzb_web::auth::{CredentialStore, StoredCredentials, TokenStore};
use nzb_web::nzb_core::config::AppConfig;
use nzb_web::nzb_core::db::Database;
use nzb_web::{AppState, LogBuffer, QueueManager};
use rustnzb::server::build_router;

struct ContractApp {
    base_url: String,
    config_path: std::path::PathBuf,
    state: Arc<AppState>,
    _temp: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ContractApp {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start_app(with_credentials: bool) -> ContractApp {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.toml");
    let config = AppConfig::default();
    config.save(&config_path).unwrap();
    let logs = LogBuffer::new();
    let queue = QueueManager::new(
        Vec::new(),
        Database::open_memory().unwrap(),
        temp.path().join("incomplete"),
        temp.path().join("complete"),
        logs.clone(),
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
    let credentials = Arc::new(CredentialStore::new(temp.path().to_path_buf()));
    if with_credentials {
        credentials
            .set_credentials(StoredCredentials {
                username: "admin".into(),
                password: "password".into(),
            })
            .unwrap();
    }
    let state = Arc::new(AppState::new(
        Arc::new(ArcSwap::from_pointee(config)),
        config_path.clone(),
        queue,
        logs,
        Arc::new(TokenStore::new()),
        credentials,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let router_state = state.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, build_router(router_state))
            .await
            .unwrap();
    });

    ContractApp {
        base_url,
        config_path,
        state,
        _temp: temp,
        handle,
    }
}

#[tokio::test]
async fn protected_routes_reject_missing_credentials_and_preserve_auth_contracts() {
    let app = start_app(true).await;
    let client = reqwest::Client::new();

    assert_eq!(
        client
            .get(format!("{}/api/config/servers", app.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(format!("{}/api/health", app.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let bad_login = client
        .post(format!("{}/api/auth/login", app.base_url))
        .json(&serde_json::json!({"username":"admin","password":"wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_login.status(), reqwest::StatusCode::UNAUTHORIZED);

    let tokens = client
        .post(format!("{}/api/auth/login", app.base_url))
        .json(&serde_json::json!({"username":"admin","password":"password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(tokens.status(), reqwest::StatusCode::OK);
    let tokens = tokens.json::<serde_json::Value>().await.unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 900);

    assert_eq!(
        client
            .get(format!("{}/api/config/servers", app.base_url))
            .bearer_auth(access)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let rotated = client
        .post(format!("{}/api/auth/refresh", app.base_url))
        .json(&serde_json::json!({"refresh_token": refresh}))
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    assert_eq!(
        client
            .post(format!("{}/api/auth/refresh", app.base_url))
            .json(&serde_json::json!({"refresh_token": refresh}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn first_boot_only_exposes_setup_and_setup_is_single_use() {
    let app = start_app(false).await;
    let client = reqwest::Client::new();

    assert_eq!(
        client
            .get(format!("{}/api/status", app.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(format!("{}/api/setup/status", app.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );

    let setup = client
        .post(format!("{}/api/auth/setup", app.base_url))
        .json(&serde_json::json!({"username":"owner","password":"secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), reqwest::StatusCode::OK);
    let access = setup.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        client
            .get(format!("{}/api/status", app.base_url))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        client
            .post(format!("{}/api/auth/setup", app.base_url))
            .json(&serde_json::json!({"username":"other","password":"secret"}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn config_routes_validate_duplicates_and_persist_successful_updates() {
    let app = start_app(false).await;
    let client = reqwest::Client::new();
    let setup = client
        .post(format!("{}/api/auth/setup", app.base_url))
        .json(&serde_json::json!({"username":"owner","password":"secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), reqwest::StatusCode::OK);
    let access = setup.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let server = serde_json::json!({
        "id":"", "name":"Primary", "host":" news.example.test ", "port":563,
        "ssl":true, "ssl_verify":true, "username":"", "password":"", "connections":8,
        "priority":0, "enabled":true, "retention":0, "pipelining":1, "optional":false,
        "compress":false, "ramp_up_delay_ms":50, "recv_buffer_size":2097152,
        "proxy_url":null, "trusted_fingerprint":null, "connect_timeout_secs":30
    });
    assert_eq!(
        client
            .post(format!("{}/api/config/servers", app.base_url))
            .bearer_auth(&access)
            .json(&server)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let servers = client
        .get(format!("{}/api/config/servers", app.base_url))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(servers.as_array().unwrap().len(), 1);
    assert_eq!(servers[0]["host"], "news.example.test");
    assert_eq!(servers[0]["username"], "");

    let category =
        serde_json::json!({"name":"tv", "output_dir":"/downloads/tv", "post_processing":3});
    assert_eq!(
        client
            .post(format!("{}/api/config/categories", app.base_url))
            .bearer_auth(&access)
            .json(&category)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        client
            .post(format!("{}/api/config/categories", app.base_url))
            .bearer_auth(&access)
            .json(&category)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );

    let feed = serde_json::json!({"name":"daily", "url":"https://example.test/feed", "poll_interval_secs":60, "category":"tv", "filter_regex":null, "enabled":true, "auto_download":false});
    assert_eq!(
        client
            .post(format!("{}/api/config/rss-feeds", app.base_url))
            .bearer_auth(&access)
            .json(&feed)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        client
            .put(format!("{}/api/config/speed-limit", app.base_url))
            .bearer_auth(&access)
            .json(&serde_json::json!({"speed_limit_bps":1234}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{}/api/config/speed-limit", app.base_url))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()["speed_limit_bps"],
        1234
    );

    let saved = AppConfig::load(&app.config_path).unwrap();
    assert_eq!(saved.servers.len(), 1);
    assert_eq!(
        saved
            .categories
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Default", "tv"]
    );
    assert_eq!(saved.rss_feeds[0].name, "daily");
    assert_eq!(saved.general.speed_limit_bps, 1234);
    assert_eq!(app.state.config().general.speed_limit_bps, 1234);
}

async fn login_access(app: &ContractApp, client: &reqwest::Client) -> String {
    client
        .post(format!("{}/api/auth/login", app.base_url))
        .json(&serde_json::json!({"username":"admin","password":"password"}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Send a request and return (status, parsed JSON body or Null).
async fn call(request: reqwest::RequestBuilder) -> (u16, serde_json::Value) {
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn unknown_ids_return_404_and_invalid_input_returns_400() {
    let app = start_app(true).await;
    let client = reqwest::Client::new();
    let access = login_access(&app, &client).await;
    let base = &app.base_url;

    // BUG-51: retry of an unknown history entry.
    let (status, body) = call(
        client
            .post(format!("{base}/api/history/no-such-id/retry"))
            .bearer_auth(&access),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error_kind"], "not_found");

    // BUG-52: out-of-range priority is a 400, unknown job a 404.
    let (status, body) = call(
        client
            .put(format!("{base}/api/queue/no-such-id/priority"))
            .bearer_auth(&access)
            .json(&serde_json::json!({"priority": 999})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error_kind"], "bad_request");
    let (status, body) = call(
        client
            .put(format!("{base}/api/queue/no-such-id/priority"))
            .bearer_auth(&access)
            .json(&serde_json::json!({"priority": 2})),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error_kind"], "job_not_found");

    // BUG-55: move of an unknown job, logs of an unknown history entry.
    let (status, body) = call(
        client
            .post(format!("{base}/api/queue/no-such-id/move"))
            .bearer_auth(&access)
            .json(&serde_json::json!({"position": 0})),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = call(
        client
            .get(format!("{base}/api/history/no-such-id/logs"))
            .bearer_auth(&access),
    )
    .await;
    assert_eq!(status, 404, "{body}");

    // BUG-55: non-numeric group id is a JSON 400 without parser internals.
    let response = client
        .get(format!("{base}/api/groups/not-a-number"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let text = response.text().await.unwrap();
    assert!(!text.contains("i64"), "{text}");
    let body: serde_json::Value = serde_json::from_str(&text).expect("JSON error body");
    assert_eq!(body["error_kind"], "bad_request");

    // BUG-56: invalid regex is a 400; updating an unknown rule is a 404;
    // deleting an unknown rule stays idempotent.
    let rule = |regex: &str| serde_json::json!({"name": "r", "feed_names": ["nope"], "match_regex": regex});
    let (status, body) = call(
        client
            .post(format!("{base}/api/rss/rules"))
            .bearer_auth(&access)
            .json(&rule("(unclosed")),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (status, body) = call(
        client
            .put(format!("{base}/api/rss/rules/no-such-rule"))
            .bearer_auth(&access)
            .json(&rule(".*")),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert!(app.state.queue_manager.rss_rule_list().unwrap().is_empty());
    let (status, _) = call(
        client
            .delete(format!("{base}/api/rss/rules/no-such-rule"))
            .bearer_auth(&access),
    )
    .await;
    assert_eq!(status, 200);

    // A rule whose feed does not exist is accepted with a warning.
    let (status, body) = call(
        client
            .post(format!("{base}/api/rss/rules"))
            .bearer_auth(&access)
            .json(&rule(".*")),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], true);
    assert!(
        body["warnings"][0].as_str().unwrap().contains("nope"),
        "{body}"
    );
}

#[tokio::test]
async fn missing_article_returns_404() {
    use nzb_nntp::testutil::{MockConfig, MockNntpServer, test_config};

    let server = MockNntpServer::start(MockConfig::default()).await;
    let app = start_app(true).await;
    app.state
        .queue_manager
        .update_servers(vec![test_config(server.port())]);
    let client = reqwest::Client::new();
    let access = login_access(&app, &client).await;

    let (status, body) = call(
        client
            .get(format!(
                "{}/api/articles/missing@example.test",
                app.base_url
            ))
            .bearer_auth(&access),
    )
    .await;
    assert_eq!(status, 404, "{body}");
}
