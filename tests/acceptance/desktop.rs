//! Native Desktop integration through the shipped binary and isolated profiles.

#[cfg(not(target_os = "macos"))]
#[test]
fn desktop_refuses_before_changing_files_on_other_platforms() {
    use crate::harness::*;
    let root = scratch("desktop-unsupported-platform");
    let (code, _, error) = cli_raw(&["desktop", "--auto"], &isolated_env(&root), None);
    assert_eq!(code, 2);
    assert!(error.contains("macOS only"));
    assert!(!root.join("Library").exists());
}

#[cfg(target_os = "macos")]
mod macos {
    use crate::client_fx::{ClientHome, install_client};
    use crate::fake_tools::FakeTools;
    use crate::harness::*;

    const MODEL: &str = "claude-sonnet-4-6";
    const TITLE_SYSTEM: &str =
        "You write short session titles. Reply with only the tagged fields the prompt asks for.";

    struct Desktop {
        client: ClientHome,
        tools: FakeTools,
        profile: PathBuf,
        runtime: PathBuf,
    }

    fn quoted(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn read(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).expect("read JSON")).expect("JSON")
    }

    impl Desktop {
        async fn new(instance: &Instance) -> Self {
            let client = install_client(instance).await;
            let profile = client.home.join("Library/Application Support/Claude-3p");
            private_dir(&profile);
            private_dir(&profile.join("configLibrary"));
            let bundle = client.home.join("Applications/Claude.app/Contents");
            fs::create_dir_all(bundle.join("Resources")).unwrap();
            fs::write(bundle.join("Info.plist"), "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleShortVersionString</key><string>2.31226.0</string></dict></plist>").unwrap();
            fs::write(bundle.join("Resources/app.asar"), "fixture app archive").unwrap();
            let tools = FakeTools::new(&client.root, &["open", "pgrep", "claude"]);
            tools.rule("pgrep", &[]).exit(1);
            tools
                .rule("claude", &["--version"])
                .stdout("2.1.293 (Claude Code)\n");
            let managed = profile.join("claude-code/2.1.293/fixture-build");
            fs::create_dir_all(managed.join("claude.app/Contents/MacOS")).unwrap();
            fs::write(managed.join(".verified"), "verified fixture").unwrap();
            let runtime = managed.join("claude.app/Contents/MacOS/claude");
            let script = format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then FAKE_TOOL_DIR={} exec {} \"$@\"; fi\n/usr/bin/env > {}\nprintf '%s\\n' \"$@\" > {}\nprintf '%s' \"$$\" > {}\ncase \"$(/bin/cat {})\" in\nhang) exec /bin/sleep 30;;\nflood) exec /usr/bin/head -c 1048577 /dev/zero;;\nfail) /bin/cat {}; exit 1;;\n*) exec /bin/cat {};;\nesac\n",
                quoted(&tools.dir),
                quoted(&tools.bin.join("claude")),
                quoted(&client.root.join("probe-env")),
                quoted(&client.root.join("probe-argv")),
                quoted(&client.root.join("probe-pid")),
                quoted(&client.root.join("probe-mode")),
                quoted(&client.root.join("probe-output")),
                quoted(&client.root.join("probe-output")),
            );
            fs::write(&runtime, script).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(client.root.join("probe-mode"), "success").unwrap();
            fs::write(client.root.join("probe-output"), json!({"type":"result", "subtype":"success", "is_error":false,
                "num_turns":1, "result":"OK", "stop_reason":"end_turn", "usage":{"input_tokens":17, "output_tokens":1}}).to_string()).unwrap();
            crate::leaks::register_planted(&client.root.join("probe-env"));
            Self {
                client,
                tools,
                profile,
                runtime,
            }
        }

        fn command(&self) -> Command {
            let mut command = self.client.command(&[]);
            command.envs(self.tools.env());
            command
        }

        fn cli(&self, args: &[&str]) -> (i32, String, String) {
            let output = self.command().args(args).output().unwrap();
            (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).into(),
                String::from_utf8_lossy(&output.stderr).into(),
            )
        }

        fn record(&self) -> PathBuf {
            self.client.client_dir.join("desktop.json")
        }

        fn spawn(&self, args: &[&str]) -> Running {
            let mut command = self.command();
            command
                .args(args)
                .env("ANTHROPIC_API_KEY", "inherited-api-key")
                .env("CLAUDE_CODE_OAUTH_TOKEN", "inherited-oauth-token")
                .env("AWS_SECRET_ACCESS_KEY", "inherited-aws-secret")
                .env("CLAUDE_CODE_USE_BEDROCK", "1")
                .env("HTTPS_PROXY", "http://inherited-proxy.invalid")
                .env("ANTHROPIC_BASE_URL", "http://inherited-origin.invalid")
                .stdout(fs::File::create(self.client.root.join("desktop-stdout")).unwrap())
                .stderr(fs::File::create(self.client.root.join("desktop-stderr")).unwrap());
            Running {
                child: command.spawn().unwrap(),
            }
        }

        async fn ready(&self, running: &mut Running) -> Gateway {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                assert!(
                    running.child.try_wait().unwrap().is_none(),
                    "adapter exited: {}",
                    self.logs()
                );
                if self.record().exists() {
                    let record = read(&self.record());
                    let gateway = Gateway {
                        addr: record["origin"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("http://")
                            .parse()
                            .unwrap(),
                        key: record["key"].as_str().unwrap().into(),
                        id: record["id"].as_str().unwrap().into(),
                    };
                    let request = gateway.authorize(
                        Request::builder()
                            .method(Method::HEAD)
                            .uri("/api/hello")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    );
                    if let Ok(answer) = try_send(gateway.addr, request).await
                        && answer.status == StatusCode::NO_CONTENT
                    {
                        crate::leaks::register_needle("Desktop local bearer", &gateway.key);
                        crate::leaks::register_planted(&self.record());
                        crate::leaks::register_planted(
                            &self
                                .profile
                                .join("configLibrary")
                                .join(format!("{}.json", gateway.id)),
                        );
                        return gateway;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "Desktop never became ready: {}",
                    self.logs()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        fn logs(&self) -> String {
            fs::read_to_string(self.client.root.join("desktop-stderr")).unwrap_or_default()
        }
    }

    struct Running {
        child: Child,
    }
    impl Running {
        async fn stop(&mut self) {
            assert!(
                Command::new("/bin/kill")
                    .args(["-TERM", &self.child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                assert!(Instant::now() < deadline, "adapter did not stop");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct Gateway {
        addr: SocketAddr,
        key: String,
        id: String,
    }
    impl Gateway {
        fn authorize(&self, mut request: Request<Full<Bytes>>) -> Request<Full<Bytes>> {
            request
                .headers_mut()
                .insert("host", self.addr.to_string().parse().unwrap());
            request.headers_mut().insert(
                "authorization",
                format!("Bearer {}", self.key).parse().unwrap(),
            );
            request
        }
        fn engine(&self, session: &str) -> Request<Full<Bytes>> {
            let mut body = prompt_for(MODEL);
            body["metadata"] = json!({"user_id": json!({"device_id":"desktop-fixture", "account_uuid":"", "session_id":session}).to_string()});
            self.authorize(with(
                in_session(messages(body), session),
                &[(
                    "user-agent",
                    "claude-cli/2.1.293 (external, claude-desktop-3p)",
                )],
            ))
        }
        fn startup(&self) -> Request<Full<Bytes>> {
            self.authorize(messages(
                json!({"model":MODEL, "max_tokens":1, "messages":[{"role":"user", "content":"."}]}),
            ))
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_preserves_body_headers_errors_and_local_isolation() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-relay").await;
        instance.add_fsub();
        let desktop = Desktop::new(&instance).await;
        let reply = Arc::new(Mutex::new(String::new()));
        let scripted = reply.clone();
        let remote = FakeControl::start(move |_| scripted.lock().unwrap().clone());
        desktop
            .client
            .set("base_url", &format!("{:?}", remote.origin()));
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        for status in [200, 401, 429, 503] {
            let body = "event: ping\ndata: {}\n\nevent: message_stop\ndata: {}\n\n";
            *reply.lock().unwrap() = format!(
                "HTTP/1.1 {status} Test\r\ncontent-type: text/event-stream\r\ncontent-encoding: identity\r\nretry-after: 7\r\nx-should-retry: false\r\nanthropic-ratelimit-unified-status: allowed\r\nx-repeat: one\r\nx-repeat: two\r\nconnection: close, x-hop\r\nx-hop: hidden\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            let request = with(
                gateway.engine("relay-session"),
                &[
                    ("cookie", "owner-cookie"),
                    ("x-api-key", "owner-key"),
                    ("proxy-authorization", "owner-proxy"),
                    ("x-jaynshare-account", "pin.untrusted"),
                    ("connection", "x-private"),
                    ("x-private", "hidden"),
                    ("anthropic-beta", "beta-one"),
                    ("anthropic-beta", "beta-two"),
                ],
            );
            let expected_body = request.body().clone().collect().await.unwrap().to_bytes();
            let answer = send(gateway.addr, request).await;
            assert_eq!(answer.status.as_u16(), status);
            assert_eq!(answer.text(), body);
            assert_eq!(answer.header("retry-after"), Some("7"));
            assert_eq!(answer.header("x-should-retry"), Some("false"));
            assert_eq!(
                answer.header("anthropic-ratelimit-unified-status"),
                Some("allowed")
            );
            assert_eq!(answer.header("content-encoding"), Some("identity"));
            assert_eq!(answer.headers.get_all("x-repeat").iter().count(), 2);
            assert!(answer.header("x-hop").is_none());
            let seen = remote.seen().pop().unwrap();
            let (headers, sent_body) = seen.split_once("\r\n\r\n").unwrap();
            assert_eq!(sent_body.as_bytes(), expected_body);
            let headers = headers.to_lowercase();
            assert!(headers.contains(&format!(
                "authorization: bearer {}",
                desktop.client.client.secret.to_lowercase()
            )));
            assert!(!seen.contains(&gateway.key));
            for stripped in [
                "owner-cookie",
                "owner-key",
                "owner-proxy",
                "pin.untrusted",
                "x-private",
            ] {
                assert!(!seen.contains(stripped));
            }
            assert!(
                headers.contains("anthropic-beta: beta-one")
                    && headers.contains("anthropic-beta: beta-two")
            );
        }
        let count = remote.seen().len();
        let mut unauthenticated = gateway.engine("wrong-auth");
        unauthenticated.headers_mut().remove("authorization");
        assert_eq!(
            send(gateway.addr, unauthenticated).await.status,
            StatusCode::UNAUTHORIZED
        );
        let mut wrong = gateway.engine("wrong-auth");
        wrong
            .headers_mut()
            .insert("authorization", "Bearer wrong".parse().unwrap());
        assert_eq!(
            send(gateway.addr, wrong).await.status,
            StatusCode::UNAUTHORIZED
        );
        let mut wrong_host = gateway.engine("wrong-host");
        wrong_host
            .headers_mut()
            .insert("host", "evil.invalid".parse().unwrap());
        assert_eq!(
            send(gateway.addr, wrong_host).await.status,
            StatusCode::FORBIDDEN
        );
        for path in [
            "/control/v1/client/status",
            "/api/oauth/profile",
            "/api/organizations",
            "/unknown",
        ] {
            assert_eq!(
                send(gateway.addr, gateway.authorize(post(path, json!({}))))
                    .await
                    .status,
                StatusCode::NOT_FOUND
            );
        }
        for request in [
            messages(prompt_for(MODEL)),
            post("/v1/messages/count_tokens", prompt_for(MODEL)),
            post("/v1/messages/count_tokens?beta=true", prompt_for(MODEL)),
        ] {
            let answer = send(gateway.addr, gateway.authorize(request)).await;
            assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED);
            assert_eq!(answer.header("x-should-retry"), Some("false"));
        }
        let models = Request::builder()
            .uri("/v1/models")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let answer = send(gateway.addr, gateway.authorize(models)).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(answer.header("x-should-retry"), Some("false"));
        assert_eq!(remote.seen().len(), count);
        running.stop().await;
        let logs = desktop.logs();
        for operation in ["count_tokens", "models", "unsupported_direct"] {
            assert!(logs.contains(&format!("operation={operation} status=501")));
        }
        assert!(logs.contains("operation=inference status=200"));
        for private in [
            "owner-cookie",
            "say hi in three words",
            "relay-session",
            &gateway.key,
            &desktop.client.client.secret,
        ] {
            assert!(!logs.contains(private));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn managed_token_counts_relay_through_the_pool() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-count-tokens").await;
        instance.add_fsub();
        let desktop = Desktop::new(&instance).await;
        let reply = Arc::new(Mutex::new(String::new()));
        let scripted = reply.clone();
        let remote = FakeControl::start(move |_| scripted.lock().unwrap().clone());
        desktop
            .client
            .set("base_url", &format!("{:?}", remote.origin()));
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        let body = json!({"model":MODEL,
            "messages":[{"role":"user", "content":"private context to count"}],
            "tools":[{"name":"local_tool", "input_schema":{"type":"object"}}]});
        for (index, status) in [200, 400, 429, 501].into_iter().enumerate() {
            let response_body = if status == 200 {
                json!({"input_tokens":37})
            } else {
                json!({"type":"error", "error":{"type":"api_error", "message":"provider count failure"}})
            }
            .to_string();
            *reply.lock().unwrap() = format!(
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\nx-should-retry: true\r\nretry-after: 7\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{response_body}",
                response_body.len()
            );
            let path = if index % 2 == 0 {
                "/v1/messages/count_tokens"
            } else {
                "/v1/messages/count_tokens?beta=true"
            };
            let request = gateway.authorize(with(
                in_session(post(path, body.clone()), "count-session"),
                &[
                    (
                        "user-agent",
                        "claude-cli/2.1.293 (external, claude-desktop-3p)",
                    ),
                    ("anthropic-beta", "token-counting-2024-11-01"),
                    ("cookie", "private-count-cookie"),
                ],
            ));
            let expected_body = request.body().clone().collect().await.unwrap().to_bytes();
            let answer = send(gateway.addr, request).await;
            assert_eq!(answer.status.as_u16(), status);
            assert_eq!(answer.text(), response_body);
            assert_eq!(answer.header("x-should-retry"), Some("true"));
            assert_eq!(answer.header("retry-after"), Some("7"));
            let seen = remote.seen().pop().unwrap();
            let (headers, sent_body) = seen.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with(&format!("POST {path} ")));
            assert!(headers.contains("x-claude-code-session-id: count-session"));
            assert!(headers.contains("anthropic-beta: token-counting-2024-11-01"));
            assert!(headers.contains(&desktop.client.client.secret));
            assert!(!seen.contains(&gateway.key) && !seen.contains("private-count-cookie"));
            assert_eq!(sent_body.as_bytes(), expected_body);
        }
        let count = remote.seen().len();
        let mut direct_probe = gateway.startup();
        *direct_probe.uri_mut() = "/v1/messages/count_tokens".parse().unwrap();
        assert_eq!(
            send(gateway.addr, direct_probe).await.status,
            StatusCode::NOT_IMPLEMENTED
        );
        assert!(!desktop.client.root.join("probe-pid").exists());
        assert_eq!(remote.seen().len(), count);
        running.stop().await;
        let logs = desktop.logs();
        assert!(logs.contains("operation=count_tokens status=200"));
        assert!(!logs.contains("desktop inference:"));
        for private in ["private context to count", "count-session", &gateway.key] {
            assert!(!logs.contains(private));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn startup_isolated_success_and_title_fallback_never_call_the_pool() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-auxiliary").await;
        let desktop = Desktop::new(&instance).await;
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        let answer = send(gateway.addr, gateway.startup()).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.json()["content"][0]["text"], "OK");
        assert_eq!(answer.json()["usage"]["input_tokens"], 17);
        let env = fs::read_to_string(desktop.client.root.join("probe-env")).unwrap();
        assert!(env.contains(&format!("ANTHROPIC_AUTH_TOKEN={}", gateway.key)));
        assert!(env.contains(&format!("ANTHROPIC_BASE_URL=http://{}", gateway.addr)));
        for value in [
            "inherited-",
            "AWS_SECRET_ACCESS_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "HTTPS_PROXY",
            &desktop.client.client.secret,
        ] {
            assert!(!env.contains(value));
        }
        let argv = fs::read_to_string(desktop.client.root.join("probe-argv")).unwrap();
        for arg in [
            "--tools\n\n",
            "--setting-sources\n\n",
            "--strict-mcp-config",
            "--no-session-persistence",
        ] {
            assert!(argv.contains(arg));
        }
        let title = gateway.authorize(messages(
            json!({"model":MODEL, "max_tokens":200, "system":TITLE_SYSTEM,
            "messages":[{"role":"user", "content":"private title input"}]}),
        ));
        let began = Instant::now();
        let answer = send(gateway.addr, title).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(answer.header("x-should-retry"), Some("false"));
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(instance.upstream.calls(), 0);
        assert!(!desktop.client.client_dir.join("desktop-probes").exists());
        running.stop().await;
        let logs = desktop.logs();
        assert!(logs.contains("operation=startup status=200"));
        assert!(logs.contains("operation=title_fallback status=501"));
        assert!(!logs.contains("private title input"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_failure_timeout_and_disconnect_reap_the_child() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-probe-failures").await;
        let desktop = Desktop::new(&instance).await;
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        for (mode, output, status) in [
            ("success", "invalid JSON", StatusCode::BAD_GATEWAY),
            ("success", "{}", StatusCode::BAD_GATEWAY),
            (
                "fail",
                "{\"api_error_status\":429}",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                "fail",
                "{\"api_error_status\":401}",
                StatusCode::UNAUTHORIZED,
            ),
            ("flood", "", StatusCode::BAD_GATEWAY),
            ("hang", "", StatusCode::GATEWAY_TIMEOUT),
        ] {
            fs::write(desktop.client.root.join("probe-mode"), mode).unwrap();
            fs::write(desktop.client.root.join("probe-output"), output).unwrap();
            let began = Instant::now();
            assert_eq!(send(gateway.addr, gateway.startup()).await.status, status);
            assert!(began.elapsed() < Duration::from_millis(9800));
            reaped(&desktop).await;
        }
        fs::remove_file(desktop.client.root.join("probe-pid")).unwrap();
        let mut socket = TcpStream::connect(gateway.addr).await.unwrap();
        let bytes = gateway
            .startup()
            .body()
            .clone()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        use tokio::io::AsyncWriteExt;
        socket.write_all(format!("POST /v1/messages HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n", gateway.addr, gateway.key, bytes.len()).as_bytes()).await.unwrap();
        socket.write_all(&bytes).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !desktop.client.root.join("probe-pid").exists() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(socket);
        reaped(&desktop).await;
        assert_eq!(instance.upstream.calls(), 0);
        running.stop().await;
    }

    async fn reaped(desktop: &Desktop) {
        let pid = fs::read_to_string(desktop.client.root.join("probe-pid")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let exists = Command::new("/bin/kill")
                .args(["-0", &pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success();
            if !exists && !desktop.client.client_dir.join("desktop-probes").exists() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the probe child was not killed and reaped"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_restart_restore_and_interrupted_setup_preserve_user_data() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-lifecycle").await;
        instance.add_fsub();
        let desktop = Desktop::new(&instance).await;
        let original_id = Uuid::new_v4().to_string();
        let config_path = desktop.profile.join("claude_desktop_config.json");
        let meta_path = desktop.profile.join("configLibrary/_meta.json");
        write_private(
            &config_path,
            "{\"deploymentMode\":\"1p\",\"theme\":\"original\"}",
        );
        write_private(&meta_path, &json!({"appliedId": original_id, "entries":[{"id":original_id,"name":"Other Gateway"}]}).to_string());
        let normal_profile = desktop
            .client
            .home
            .join("Library/Application Support/Claude");
        fs::create_dir_all(&normal_profile).unwrap();
        fs::write(
            normal_profile.join("claude_desktop_config.json"),
            "normal profile untouched",
        )
        .unwrap();
        fs::write(
            desktop.profile.join("conversation-history"),
            "local history preserved",
        )
        .unwrap();
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        let installed = read(&desktop.record());
        let gateway_path = desktop
            .profile
            .join("configLibrary")
            .join(format!("{}.json", gateway.id));
        let mut entry = read(&gateway_path);
        assert_eq!(entry["disableAutoUpdates"], true);
        entry["uiHint"] = json!("user preference");
        write_private(&gateway_path, &entry.to_string());
        assert_ne!(gateway.key, desktop.client.client.secret);
        assert_eq!(desktop.cli(&["desktop", "--auto"]).0, 0);
        assert_eq!(read(&desktop.record()), installed);
        assert_eq!(read(&gateway_path), entry);
        assert_eq!(desktop.cli(&["desktop", "--account", "FSUB"]).0, 1);
        assert_eq!(desktop.cli(&["desktop", "--restore"]).0, 1);
        running.stop().await;
        let occupied = StdTcpListener::bind(gateway.addr).unwrap();
        let (code, _, error) = desktop.cli(&["desktop", "--auto"]);
        assert_eq!(code, 1);
        assert!(error.contains("port is occupied"));
        assert_eq!(read(&desktop.record()), installed);
        drop(occupied);
        // Upgrade the first RC's entry without replacing its credential or user preferences.
        let mut legacy = entry.clone();
        legacy.as_object_mut().unwrap().remove("disableAutoUpdates");
        write_private(&gateway_path, &legacy.to_string());
        // Simulate interruption after the record and entry, before selection commits.
        write_private(
            &config_path,
            "{\"deploymentMode\":\"1p\",\"theme\":\"changed\"}",
        );
        write_private(
            &meta_path,
            &json!({"appliedId":original_id,"entries":[{"id":original_id,"name":"Other Gateway"}]})
                .to_string(),
        );
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let restarted = desktop.ready(&mut running).await;
        assert_eq!(restarted.addr, gateway.addr);
        assert_eq!(restarted.key, gateway.key);
        assert_eq!(read(&desktop.record()), installed);
        assert_eq!(read(&config_path)["theme"], "changed");
        assert_eq!(read(&gateway_path), entry);
        running.stop().await;
        let mut config = read(&config_path);
        config["theme"] = json!("Desktop saved preference");
        write_private(&config_path, &config.to_string());
        let new_id = Uuid::new_v4().to_string();
        let mut meta = read(&meta_path);
        meta["appliedId"] = json!(new_id);
        meta["hybridPointer"] = json!({"url":"https://policy.invalid"});
        meta["entries"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":new_id,"name":"User's new Gateway"}));
        write_private(&meta_path, &meta.to_string());
        assert_eq!(desktop.cli(&["desktop", "--restore"]).0, 0);
        assert_eq!(
            read(&config_path),
            json!({"deploymentMode":"1p", "theme":"Desktop saved preference"})
        );
        assert_eq!(read(&meta_path)["appliedId"], new_id);
        assert_eq!(
            read(&meta_path)["hybridPointer"]["url"],
            "https://policy.invalid"
        );
        assert_eq!(read(&meta_path)["entries"].as_array().unwrap().len(), 2);
        assert!(!desktop.record().exists());
        assert_eq!(read(&gateway_path), json!({"uiHint":"user preference"}));
        assert_eq!(
            fs::read_to_string(normal_profile.join("claude_desktop_config.json")).unwrap(),
            "normal profile untouched"
        );
        assert_eq!(
            fs::read_to_string(desktop.profile.join("conversation-history")).unwrap(),
            "local history preserved"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn version_runtime_and_managed_profile_changes_fail_before_setup() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-compatibility").await;
        let desktop = Desktop::new(&instance).await;
        let plist = desktop
            .client
            .home
            .join("Applications/Claude.app/Contents/Info.plist");
        let original = fs::read_to_string(&plist).unwrap();
        fs::write(&plist, original.replace("2.31226.0", "9.0.0")).unwrap();
        assert_eq!(desktop.cli(&["desktop", "--auto"]).0, 1);
        assert!(!desktop.record().exists());
        assert!(!desktop.profile.join("claude_desktop_config.json").exists());
        fs::write(&plist, original).unwrap();
        let marker = desktop
            .runtime
            .ancestors()
            .nth(4)
            .unwrap()
            .join(".verified");
        fs::remove_file(&marker).unwrap();
        assert_eq!(desktop.cli(&["desktop", "--auto"]).0, 1);
        assert!(!desktop.record().exists());
        fs::write(marker, "verified fixture").unwrap();
        let meta_path = desktop.profile.join("configLibrary/_meta.json");
        write_private(
            &meta_path,
            "{\"hybridPointer\":{\"url\":\"https://policy.invalid\"}}",
        );
        assert_eq!(desktop.cli(&["desktop", "--auto"]).0, 1);
        assert!(!desktop.record().exists());
        fs::remove_file(meta_path).unwrap();
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        fs::write(&desktop.runtime, "replacement runtime").unwrap();
        if let Ok(answer) = tokio::time::timeout(
            Duration::from_secs(2),
            try_send(gateway.addr, gateway.engine("changed-runtime")),
        )
        .await
        .unwrap()
        {
            assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = running.child.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(desktop.logs().contains("runtime changed"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pinned_and_auto_sessions_resume_without_mid_chat_failover() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-session-selection").await;
        add_two(&instance);
        let desktop = Desktop::new(&instance).await;
        let mut running = desktop.spawn(&["desktop", "--account", "FSUB2"]);
        let gateway = desktop.ready(&mut running).await;
        assert_eq!(
            send(gateway.addr, gateway.engine("pinned-conversation"))
                .await
                .status,
            StatusCode::OK
        );
        assert_eq!(
            instance.last_record(1)["serving_account"]["display_name"],
            "FSUB2"
        );
        let metadata: Value = serde_json::from_str(
            instance.upstream.last().json()["metadata"]["user_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metadata["account_uuid"], FSUB2_UUID);
        running.stop().await;
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        assert_eq!(
            send(gateway.addr, gateway.engine("pinned-conversation"))
                .await
                .status,
            StatusCode::OK
        );
        assert_eq!(
            instance.last_record(2)["serving_account"]["display_name"],
            "FSUB2"
        );
        assert_eq!(
            send(gateway.addr, gateway.engine("automatic-conversation"))
                .await
                .status,
            StatusCode::OK
        );
        instance.last_record(3);
        instance.upstream.script([reply_exhausted_429(60)]);
        assert_eq!(
            send(gateway.addr, gateway.engine("pinned-conversation"))
                .await
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        instance.last_record(4);
        let calls = instance.upstream.calls();
        assert_eq!(
            send(gateway.addr, gateway.engine("pinned-conversation"))
                .await
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(instance.upstream.calls(), calls);
        assert_eq!(instance.last_record(5)["session_id"], "pinned-conversation");
        assert_eq!(
            send(gateway.addr, gateway.engine("new-conversation"))
                .await
                .status,
            StatusCode::OK
        );
        assert_eq!(
            instance.last_record(6)["serving_account"]["display_name"],
            "FSUB"
        );
        running.stop().await;
        assert_eq!(desktop.cli(&["uninstall"]).0, 0);
        assert!(
            !desktop
                .profile
                .join("configLibrary")
                .join(format!("{}.json", gateway.id))
                .exists()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_auth_pin_outage_and_body_limits_are_enforced() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-trust").await;
        instance.add_fsub();
        let desktop = Desktop::new(&instance).await;
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        let credential = desktop.client.client_dir.join("client-secret");
        let calls = instance.upstream.calls();
        write_private(&credential, "invalid-client-secret");
        assert_eq!(
            send(gateway.addr, gateway.engine("bad-client-auth"))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(instance.upstream.calls(), calls);
        write_private(&credential, &desktop.client.client.secret);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = TcpStream::connect(gateway.addr).await.unwrap();
        socket.write_all(format!("POST /v1/messages HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 33554433\r\nConnection: close\r\n\r\n", gateway.addr, gateway.key).as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parse_answer(&raw).status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(instance.upstream.calls(), calls);
        assert_eq!(
            instance
                .cli(
                    &["--yes", "client", "revoke", &desktop.client.client.id],
                    None
                )
                .0,
            0
        );
        assert_eq!(
            send(gateway.addr, gateway.engine("revoked-client"))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        running.stop().await;
        let pair = scratch("desktop-wrong-pin-pair");
        let origin = tls_front(instance.addr, &pair).await;
        desktop.client.set("base_url", &format!("{origin:?}"));
        let mut text = fs::read_to_string(desktop.client.client_dir.join("client.toml")).unwrap();
        text.push_str(
            "server_identity = \"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n",
        );
        write_private(&desktop.client.client_dir.join("client.toml"), &text);
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        assert_eq!(
            send(gateway.addr, gateway.engine("wrong-remote-pin"))
                .await
                .status,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(instance.upstream.calls(), calls);
        running.stop().await;
        fs::write(
            desktop.client.client_dir.join("client.toml"),
            text.replace(
                "server_identity = \"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n",
                "",
            ),
        )
        .unwrap();
        let unavailable = StdTcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        desktop
            .client
            .set("base_url", &format!("\"http://{unavailable}\""));
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        assert_eq!(
            send(gateway.addr, gateway.engine("pool-outage"))
                .await
                .status,
            StatusCode::BAD_GATEWAY
        );
        running.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inference_streams_preserve_pings_backpressure_and_cancellation() {
        let _leak_sweep = crate::leaks::LeakGuard::default();
        let instance = Instance::start_client("desktop-streams").await;
        instance.add_fsub();
        let desktop = Desktop::new(&instance).await;
        let mut running = desktop.spawn(&["desktop", "--auto"]);
        let gateway = desktop.ready(&mut running).await;
        let mut events = sse_events();
        events.insert(1, "event: ping\ndata: {}\n\n".into());
        instance.upstream.script([Reply::Sse {
            events: events.clone(),
        }]);
        let mut stream =
            open_without_reading(gateway.addr, gateway.engine("sse-conversation")).await;
        let first = stream.next_frame().await.unwrap();
        let mut body = first.to_vec();
        body.extend(stream.drain().await.body());
        assert_eq!(String::from_utf8(body).unwrap(), events.concat());
        let (delivered, dropped) = watched();
        instance.upstream.script([Reply::SseWatched {
            events: (0..16).map(|_| "x".repeat(2 * 1024 * 1024)).collect(),
            gap_ms: 30,
            delivered: delivered.clone(),
            dropped: dropped.clone(),
        }]);
        let mut stalled =
            open_without_reading(gateway.addr, gateway.engine("stalled-stream")).await;
        let first = stalled.next_frame().await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(delivered.load(Ordering::Relaxed) < 16);
        let answer = stalled.drain().await;
        assert_eq!(first.len() + answer.body().len(), 32 * 1024 * 1024);
        let (delivered, dropped) = watched();
        instance.upstream.script([Reply::SseWatched {
            events: (0..60).map(|_| "x".repeat(2 * 1024 * 1024)).collect(),
            gap_ms: 100,
            delivered: delivered.clone(),
            dropped: dropped.clone(),
        }]);
        let mut leaving =
            open_without_reading(gateway.addr, gateway.engine("cancelled-stream")).await;
        leaving.next_frame().await.unwrap();
        drop(leaving);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !dropped.load(Ordering::Relaxed) {
            assert!(
                Instant::now() < deadline,
                "disconnect did not cancel the upstream stream"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(delivered.load(Ordering::Relaxed) < 30);
        running.stop().await;
    }
}
