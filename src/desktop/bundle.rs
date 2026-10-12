//! Read Desktop's embedded runtime manifest without executing its JavaScript.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;

#[derive(Debug)]
pub struct Runtime {
    pub version: String,
    pub checksum: String,
}

pub fn runtime(path: &Path) -> Result<Runtime, String> {
    read_runtime(path).map_err(|why| {
        format!(
            "cannot check Desktop's bundled runtime: {why}; update Jaynshare for this Desktop build"
        )
    })
}

fn read_runtime(path: &Path) -> Result<Runtime, String> {
    let mut archive = File::open(path).map_err(|e| e.to_string())?;
    let length = archive.metadata().map_err(|e| e.to_string())?.len();
    let mut prefix = [0; 16];
    archive.read_exact(&mut prefix).map_err(|e| e.to_string())?;
    let number =
        |offset| u32::from_le_bytes(prefix[offset..offset + 4].try_into().expect("four bytes"));
    let header_size = u64::from(number(4));
    let json_size = u64::from(number(12));
    let start = header_size
        .checked_add(8)
        .ok_or("archive header overflow")?;
    if number(0) != 4
        || json_size > 8 * 1024 * 1024
        || json_size + 8 > header_size
        || start > length
    {
        return Err("invalid app.asar header".into());
    }
    let mut bytes = vec![0; json_size as usize];
    archive.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    let header: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let files = header["files"][".vite"]["files"]["build"]["files"]
        .as_object()
        .ok_or("Desktop's main JavaScript directory is missing")?;
    let mut found = None;
    let mut read = 0_u64;
    for (name, entry) in files {
        if !name.starts_with("index") || !name.ends_with(".js") || entry["unpacked"] == true {
            continue;
        }
        let size = entry["size"].as_u64().ok_or("invalid module size")?;
        read = read.checked_add(size).ok_or("module sizes overflow")?;
        if size > 16 * 1024 * 1024 || read > 64 * 1024 * 1024 {
            return Err("Desktop's main JavaScript exceeds the inspection limit".into());
        }
        let offset = entry["offset"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .and_then(|offset| start.checked_add(offset))
            .filter(|offset| offset.checked_add(size).is_some_and(|end| end <= length))
            .ok_or("invalid module offset")?;
        archive
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        let mut source = vec![0; size as usize];
        archive.read_exact(&mut source).map_err(|e| e.to_string())?;
        let source = std::str::from_utf8(&source).map_err(|e| e.to_string())?;
        // shortcut: Desktop currently embeds literal JSON in JSON.parse; changed packaging needs a new reader.
        for literal in source.split("JSON.parse('").skip(1) {
            let Some(Ok(value)) = serde_json::Deserializer::from_str(literal)
                .into_iter::<Value>()
                .next()
            else {
                continue;
            };
            let Some(runtime) = manifest(&value)? else {
                continue;
            };
            if found.is_some() {
                return Err("Desktop's runtime manifest is ambiguous".into());
            }
            found = Some(runtime);
        }
    }
    found.ok_or_else(|| "Desktop's runtime manifest was not found".into())
}

fn manifest(value: &Value) -> Result<Option<Runtime>, String> {
    let manifest = &value["manifest"];
    let code_release = value["baseUrl"]
        .as_str()
        .and_then(|s| s.parse::<http::Uri>().ok())
        .is_some_and(|uri| {
            uri.path()
                .split('/')
                .any(|part| part == "claude-code-releases")
        });
    if !code_release || !manifest["platforms"].is_object() {
        return Ok(None);
    }
    let version = value["version"]
        .as_str()
        .ok_or("runtime version is missing")?;
    if version.split('.').count() != 3
        || version.split('.').any(|part| {
            part.is_empty() || part.len() > 6 || !part.bytes().all(|b| b.is_ascii_digit())
        })
        || manifest["version"] != version
    {
        return Err("invalid runtime version".into());
    }
    let platform = match std::env::consts::ARCH {
        "aarch64" => "darwin-arm64",
        "x86_64" => "darwin-x64",
        _ => return Err("unsupported macOS runtime architecture".into()),
    };
    let checksum = manifest["platforms"][platform]["bundle"]["checksum"]
        .as_str()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or("Desktop's managed bundle checksum is missing or invalid")?;
    Ok(Some(Runtime {
        version: version.into(),
        checksum: checksum.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inspect(header: Value, source: &[u8]) -> Result<Runtime, String> {
        let header = header.to_string();
        let padding = (4 - header.len() % 4) % 4;
        let header_size = header.len() + padding + 8;
        let mut bytes = Vec::new();
        for number in [
            4,
            header_size as u32,
            (header_size - 4) as u32,
            header.len() as u32,
        ] {
            bytes.extend_from_slice(&number.to_le_bytes());
        }
        bytes.extend_from_slice(header.as_bytes());
        bytes.resize(8 + header_size, 0);
        bytes.extend_from_slice(source);
        let path = std::env::temp_dir().join(format!(
            "jaynshare-bundle-test-{}.asar",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, bytes).unwrap();
        let result = runtime(&path);
        std::fs::remove_file(path).unwrap();
        result
    }

    #[test]
    fn archive_offsets_sizes_and_manifest_ambiguity_are_checked() {
        let value = json!({"version":"2.9.123", "baseUrl":"https://downloads.claude.ai/claude-code-releases", "manifest":{"version":"2.9.123", "platforms":{
            "darwin-arm64":{"bundle":{"checksum":"a".repeat(64)}},
            "darwin-x64":{"bundle":{"checksum":"a".repeat(64)}}}}});
        let source = format!("JSON.parse('{value}')");
        let mut header = json!({"files":{".vite":{"files":{"build":{"files":{"index.js":{"size":source.len(),"offset":"0"}}}}}}});
        assert_eq!(
            inspect(header.clone(), source.as_bytes()).unwrap().version,
            "2.9.123"
        );
        let entry = &mut header["files"][".vite"]["files"]["build"]["files"]["index.js"];
        entry["offset"] = json!(u64::MAX.to_string());
        assert!(
            inspect(header.clone(), source.as_bytes())
                .unwrap_err()
                .contains("invalid module offset")
        );
        let entry = &mut header["files"][".vite"]["files"]["build"]["files"]["index.js"];
        entry["offset"] = json!("0");
        entry["size"] = json!(u64::MAX);
        assert!(
            inspect(header.clone(), source.as_bytes())
                .unwrap_err()
                .contains("inspection limit")
        );
        header["files"][".vite"]["files"]["build"]["files"]["index.js"]["size"] =
            json!(source.len());
        header["files"][".vite"]["files"]["build"]["files"]["index.chunk-other.js"] =
            json!({"size":source.len(),"offset":source.len().to_string()});
        let duplicated = format!("{source}{source}");
        assert!(
            inspect(header, duplicated.as_bytes())
                .unwrap_err()
                .contains("ambiguous")
        );
    }

    #[test]
    fn validates_runtime_manifest_and_rejects_path_components() {
        let mut value = json!({"version":"2.9.123", "baseUrl":"https://downloads.claude.ai/claude-code-releases", "manifest":{"version":"2.9.123", "platforms":{
            "darwin-arm64":{"bundle":{"checksum":"a".repeat(64)}},
            "darwin-x64":{"bundle":{"checksum":"a".repeat(64)}}}}});
        assert_eq!(manifest(&value).unwrap().unwrap().version, "2.9.123");
        value["version"] = json!("../../escape");
        assert!(manifest(&value).is_err());
        value["baseUrl"] = json!("https://downloads.claude.ai/claude-ssh-releases");
        assert!(manifest(&value).unwrap().is_none());
        assert!(manifest(&json!({"version":"1.0.0"})).unwrap().is_none());
    }
}
