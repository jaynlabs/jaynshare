//! The client kit the server offers: its version and per-platform payload
//! digests in the client snapshot, and the kit itself at
//! `GET /control/v1/client/kit`, which a client verifies against its own
//! pinned key before it follows.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, ReadBuf};

use crate::bundle::{self, PAYLOADS};
use crate::data_plane::relay::{BoxError, ResponseBody};
use crate::server::Server;

use super::error;

/// The offered kit's version and each platform's payload SHA-256.
#[derive(Clone)]
pub struct Offer {
    version: String,
    sha256: BTreeMap<&'static str, String>,
}

impl Offer {
    /// The snapshot's `client.version` and `client.sha256`.
    pub fn members(&self) -> [(&'static str, Value); 2] {
        [
            ("version", json!(self.version)),
            ("sha256", json!(self.sha256)),
        ]
    }
}

/// The file a verdict was reached on: an update or a rollback switches the
/// `current` link, which changes the resolved path.
#[derive(Clone, PartialEq)]
struct Identity {
    path: PathBuf,
    length: u64,
    modified: Option<SystemTime>,
}

fn identify(path: &Path) -> Option<Identity> {
    let path = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&path).ok()?;
    Some(Identity {
        length: metadata.len(),
        modified: metadata.modified().ok(),
        path,
    })
}

#[derive(Default)]
pub struct KitCache(Mutex<Verdicts>);

#[derive(Default)]
struct Verdicts {
    /// The file the offer was decided on (`None`: no file), and the offer.
    decided: Option<(Option<Identity>, Option<Offer>)>,
    /// The file being verified in the background.
    verifying: Option<Identity>,
}

/// The configured kit, or `None` while it is missing, unverified or fails
/// this server's own verification. Verifying reads the whole kit, so a
/// changed kit is verified off the request path and offered once it passes.
pub fn offer(server: &Arc<Server>) -> Option<Offer> {
    let path = server.config().config.clients.kit_file.clone();
    let identity = identify(&path);
    let mut verdicts = server.client_kit.0.lock().expect("kit cache lock");
    if let Some((decided, offer)) = &verdicts.decided
        && *decided == identity
    {
        return offer.clone();
    }
    let Some(identity) = identity else {
        tracing::info!(event = "client_kit", path = %path.display(), "no client kit: clients are offered no update");
        verdicts.decided = Some((None, None));
        return None;
    };
    if verdicts.verifying.as_ref() != Some(&identity) {
        verdicts.verifying = Some(identity.clone());
        let server = Arc::clone(server);
        tokio::task::spawn_blocking(move || {
            let offer = verify(&path);
            let mut verdicts = server.client_kit.0.lock().expect("kit cache lock");
            if verdicts.verifying.as_ref() == Some(&identity) {
                verdicts.verifying = None;
            }
            verdicts.decided = Some((Some(identity), offer));
        });
    }
    None
}

fn verify(path: &Path) -> Option<Offer> {
    match read_offer(path) {
        Ok(offer) => {
            tracing::info!(event = "client_kit", path = %path.display(), version = %offer.version, "clients follow this client kit");
            Some(offer)
        }
        Err(why) => {
            tracing::warn!(event = "client_kit", path = %path.display(), reason = %why, "the client kit fails verification: clients are offered no update");
            None
        }
    }
}

fn read_offer(path: &Path) -> Result<Offer, String> {
    let key = crate::deploy::release::active_key()?;
    let kit = bundle::verify_kit_zip(path, &key)?;
    let sha256 = PAYLOADS
        .into_iter()
        .filter_map(|(platform, member)| Some((platform, bundle::sha256_hex(kit.member(member)?))))
        .collect();
    Ok(Offer {
        version: kit.version,
        sha256,
    })
}

/// `GET /control/v1/client/kit`: the offered kit, streamed as it is on disk.
pub(super) async fn download(server: &Arc<Server>) -> Response<ResponseBody> {
    let path = server.config().config.clients.kit_file.clone();
    let file = match offer(server) {
        Some(_) => tokio::fs::File::open(&path).await.ok(),
        None => None,
    };
    let length = match &file {
        Some(file) => file.metadata().await.ok().map(|m| m.len()),
        None => None,
    };
    let (Some(file), Some(length)) = (file, length) else {
        return error(
            StatusCode::NOT_FOUND,
            "not_found",
            "this server offers no client kit",
            None,
            vec![],
        );
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(CONTENT_LENGTH, length)
        .body(BoxBody::new(FileBody {
            file,
            buffer: vec![0; 64 * 1024].into_boxed_slice(),
        }))
        .expect("the kit response builds")
}

struct FileBody {
    file: tokio::fs::File,
    buffer: Box<[u8]>,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let mut read = ReadBuf::new(&mut this.buffer);
        Poll::Ready(
            match ready!(Pin::new(&mut this.file).poll_read(cx, &mut read)) {
                Err(e) => Some(Err(e.into())),
                Ok(()) if read.filled().is_empty() => None,
                Ok(()) => Some(Ok(Frame::data(Bytes::copy_from_slice(read.filled())))),
            },
        )
    }
}
