//! Wire capture: one file per exchange, credentials replaced by a placeholder
//! naming only the kind.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, Method, StatusCode, Uri, Version};
use uuid::Uuid;

use crate::provider::anthropic::X_API_KEY;
use crate::state::{ensure_private_dir, open_private};

const PROXY_AUTHORIZATION: HeaderName = HeaderName::from_static("proxy-authorization");

#[derive(Debug, Clone)]
pub struct Capture {
    directory: PathBuf,
}

impl Capture {
    pub fn open(directory: &Path) -> io::Result<Self> {
        ensure_private_dir(directory)?;
        Ok(Self {
            directory: directory.to_path_buf(),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn begin(&self, exchange_id: Uuid) -> io::Result<ExchangeCapture> {
        let file = open_private(&self.directory.join(format!("{exchange_id}.txt")))?;
        Ok(ExchangeCapture { file })
    }
}

/// Synchronous writes from async code; capture is a debugging feature and
/// its files are small. Move to a blocking task if it ever shows in a profile.
#[derive(Debug)]
pub struct ExchangeCapture {
    file: File,
}

impl ExchangeCapture {
    pub fn request(
        &mut self,
        method: &Method,
        uri: &Uri,
        version: Version,
        headers: &HeaderMap,
        body: &[u8],
    ) {
        let _ = writeln!(self.file, "=== request\n{method} {uri} {version:?}");
        self.headers(headers);
        let _ = self.file.write_all(body);
        let _ = writeln!(self.file);
    }

    pub fn attempt(
        &mut self,
        number: u32,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) {
        let _ = writeln!(self.file, "=== attempt {number}\n{method} {uri}");
        self.headers(headers);
        let _ = self.file.write_all(body);
        let _ = writeln!(self.file);
    }

    pub fn response(&mut self, status: StatusCode, headers: &HeaderMap) {
        let _ = writeln!(self.file, "=== response\n{status}");
        self.headers(headers);
    }

    pub fn body_chunk(&mut self, chunk: &[u8]) {
        let _ = self.file.write_all(chunk);
    }

    fn headers(&mut self, headers: &HeaderMap) {
        for (name, value) in headers {
            let shown = if *name == AUTHORIZATION || *name == PROXY_AUTHORIZATION {
                let kind = value
                    .to_str()
                    .ok()
                    .and_then(|v| v.split_whitespace().next())
                    .unwrap_or("credential");
                format!("{kind} <redacted>")
            } else if *name == X_API_KEY {
                "<redacted api key>".to_string()
            } else {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            };
            let _ = writeln!(self.file, "{name}: {shown}");
        }
        let _ = writeln!(self.file);
    }
}
