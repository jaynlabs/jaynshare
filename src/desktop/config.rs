//! Recoverable, field-level ownership of the separate third-party profile.

use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::ClientInstallation;
use crate::state;

pub const MODEL: &str = "claude-sonnet-4-6";
const RECORD: &str = "desktop.json";

pub fn profile() -> PathBuf {
    crate::config::platform::home().join("Library/Application Support/Claude-3p")
}

pub fn lock(directory: &Path) -> Result<File, String> {
    state::check_private(directory)?;
    let path = directory.join("desktop.lock");
    // Truncating the lock file does not replace its inode or release another process's lock.
    let file = state::open_private(&path).map_err(|e| e.to_string())?;
    file.try_lock().map_err(|_| "a Desktop adapter is already running; stop its foreground command before restore or changing accounts".to_string())?;
    Ok(file)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integration {
    version: u32,
    pub id: String,
    pub origin: String,
    pub key: String,
    pub selector: Option<String>,
    pub client_id: String,
    pub server: String,
    pub pin: Option<String>,
    deployment_before: Option<Value>,
    applied_before: Option<Value>,
}

impl Integration {
    pub fn read(directory: &Path) -> Result<Option<Self>, String> {
        let path = directory.join(RECORD);
        if !path.exists() {
            return Ok(None);
        }
        state::check_private(&path)?;
        let record: Self = serde_json::from_value(read_object(&path)?)
            .map_err(|e| format!("invalid Desktop recovery record: {e}"))?;
        let uri: http::Uri = record
            .origin
            .parse()
            .map_err(|_| "invalid Desktop origin")?;
        if record.version != 1
            || uuid::Uuid::parse_str(&record.id).is_err()
            || uri.scheme_str() != Some("http")
            || uri.host() != Some("127.0.0.1")
            || uri.port_u16().is_none_or(|p| p == 0)
            || uri.path() != "/"
            || uri.query().is_some()
            || record.key.is_empty()
            || http::HeaderValue::from_str(&format!("Bearer {}", record.key)).is_err()
            || record.selector.as_deref().is_some_and(|s| {
                !matches!(
                    crate::data_plane::intent::parse_token(s),
                    Ok(crate::data_plane::intent::Intent::Pin(_))
                )
            })
        {
            return Err("unsupported Desktop recovery record".into());
        }
        Ok(Some(record))
    }

    pub fn new(
        installation: &ClientInstallation,
        origin: String,
        selector: Option<String>,
    ) -> Result<Self, String> {
        let (config, meta) = documents()?;
        Ok(Self {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            origin,
            key: crate::secret::Secret::generate(crate::secret::Role::ClientSecret).into_string(),
            selector,
            client_id: installation.client_id.clone(),
            server: installation.base_url.clone(),
            pin: installation.server_identity.clone(),
            deployment_before: config.get("deploymentMode").cloned(),
            applied_before: meta.get("appliedId").cloned(),
        })
    }

    pub fn save(&self, directory: &Path) -> Result<(), String> {
        write(
            &directory.join(RECORD),
            &serde_json::to_value(self).map_err(|e| e.to_string())?,
        )
    }

    fn gateway(&self) -> Value {
        json!({
            "inferenceProvider": "gateway", "inferenceCredentialKind": "static",
            "inferenceGatewayBaseUrl": self.origin, "inferenceGatewayApiKey": self.key,
            "inferenceGatewayAuthScheme": "bearer", "chatTabEnabled": true,
            "modelDiscoveryEnabled": false, "inferenceModels": [MODEL],
            "disableEssentialTelemetry": true, "disableNonessentialTelemetry": true,
        })
    }

    fn entry(&self) -> Value {
        json!({"id": self.id, "name": "Jaynshare"})
    }

    fn gateway_path(&self) -> PathBuf {
        profile()
            .join("configLibrary")
            .join(format!("{}.json", self.id))
    }

    fn gateway_matches(&self, current: &Value) -> bool {
        self.gateway()
            .as_object()
            .expect("Gateway object")
            .iter()
            .all(|(field, installed)| current.get(field) == Some(installed))
    }

    pub fn installed(&self) -> Result<bool, String> {
        let (config, meta) = documents()?;
        Ok(config["deploymentMode"] == "3p"
            && meta["appliedId"] == self.id
            && meta["entries"]
                .as_array()
                .is_some_and(|entries| entries.contains(&self.entry()))
            && self.gateway_path().exists()
            && self.gateway_matches(&read_object(&self.gateway_path())?))
    }

    pub fn install(&self) -> Result<(), String> {
        let (mut config, mut meta) = documents()?;
        if self.gateway_path().exists()
            && !self.gateway_matches(&read_object(&self.gateway_path())?)
        {
            return Err("the Jaynshare Gateway entry was changed; run `jaynshare desktop --restore` before setup".into());
        }
        for (current, before, installed) in [
            (
                config.get("deploymentMode"),
                self.deployment_before.as_ref(),
                json!("3p"),
            ),
            (
                meta.get("appliedId"),
                self.applied_before.as_ref(),
                json!(self.id),
            ),
        ] {
            if current != before && current != Some(&installed) {
                return Err("Desktop selection changed since setup; restore the integration before selecting it again".into());
            }
        }
        let entries = meta["entries"]
            .as_array_mut()
            .expect("documents validates entries");
        if entries
            .iter()
            .any(|entry| entry["id"] == self.id && entry != &self.entry())
        {
            return Err("the Jaynshare library entry was changed; restore before setup".into());
        }
        if !entries.contains(&self.entry()) {
            entries.push(self.entry());
        }
        meta["appliedId"] = json!(self.id);
        config["deploymentMode"] = json!("3p");
        state::ensure_private_dir(&profile()).map_err(|e| e.to_string())?;
        state::check_private(&profile())?;
        state::ensure_private_dir(&profile().join("configLibrary")).map_err(|e| e.to_string())?;
        state::check_private(&profile().join("configLibrary"))?;
        if !self.gateway_path().exists() {
            write(&self.gateway_path(), &self.gateway())?;
        }
        write(&profile().join("configLibrary/_meta.json"), &meta)?;
        write(&profile().join("claude_desktop_config.json"), &config)
    }

    pub fn restore(&self, directory: &Path) -> Result<(), String> {
        let (mut config, mut meta) = profile_documents()?;
        restore_field(
            &mut config,
            "deploymentMode",
            &json!("3p"),
            &self.deployment_before,
        );
        restore_field(
            &mut meta,
            "appliedId",
            &json!(self.id),
            &self.applied_before,
        );
        meta["entries"]
            .as_array_mut()
            .expect("validated entries")
            .retain(|entry| entry["id"] != self.id);
        let gateway = self.gateway_path();
        if gateway.exists() {
            let mut current = read_object(&gateway)?;
            for (field, value) in self.gateway().as_object().expect("Gateway object") {
                if current.get(field) == Some(value) {
                    current.as_object_mut().expect("read_object").remove(field);
                }
            }
            // Credentials in this entry belong only to the local adapter, even after user edits.
            current
                .as_object_mut()
                .expect("read_object")
                .remove("inferenceGatewayApiKey");
            if current.as_object().expect("read_object").is_empty() {
                fs::remove_file(&gateway).map_err(|e| e.to_string())?;
            } else {
                write(&gateway, &current)?;
            }
        }
        if profile().join("claude_desktop_config.json").exists() {
            write(&profile().join("claude_desktop_config.json"), &config)?;
        }
        if profile().join("configLibrary/_meta.json").exists() {
            write(&profile().join("configLibrary/_meta.json"), &meta)?;
        }
        cleanup_probes(directory)?;
        fs::remove_file(directory.join(RECORD)).map_err(|e| e.to_string())
    }
}

pub fn cleanup_probes(directory: &Path) -> Result<(), String> {
    match fs::remove_dir_all(directory.join("desktop-probes")) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "could not remove the isolated Desktop probe state: {e}"
        )),
    }
}

fn restore_field(document: &mut Value, field: &str, installed: &Value, before: &Option<Value>) {
    if document.get(field) != Some(installed) {
        return;
    }
    match before {
        Some(value) => document[field] = value.clone(),
        None => {
            document.as_object_mut().expect("object").remove(field);
        }
    }
}

fn documents() -> Result<(Value, Value), String> {
    let (config, meta) = profile_documents()?;
    if meta.get("hybridPointer").is_some() {
        return Err(
            "Desktop uses a managed Gateway policy; ask its administrator to configure it".into(),
        );
    }
    Ok((config, meta))
}

fn profile_documents() -> Result<(Value, Value), String> {
    let config = read_object(&profile().join("claude_desktop_config.json"))?;
    let mut meta = read_object(&profile().join("configLibrary/_meta.json"))?;
    if !matches!(config.get("deploymentMode"), None | Some(Value::String(_)))
        || !matches!(meta.get("appliedId"), None | Some(Value::String(_)))
    {
        return Err("unsupported Desktop configuration format".into());
    }
    if meta.get("entries").is_none() {
        meta["entries"] = json!([]);
    }
    if !meta["entries"].as_array().is_some_and(|entries| {
        entries.iter().all(|e| {
            e["id"]
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                && e["name"].is_string()
        })
    }) {
        return Err("unsupported Desktop configLibrary format".into());
    }
    Ok((config, meta))
}

fn read_object(path: &Path) -> Result<Value, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(json!({})),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if !value.is_object() {
        return Err(format!("{}: expected a JSON object", path.display()));
    }
    Ok(value)
}

fn write(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    state::write_private_atomic(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
}
