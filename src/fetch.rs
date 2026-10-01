//! Optional bounded HTTPS fetching with exact origin allowlists, no redirects or
//! proxies, and connections pinned to the public addresses that were checked.
use crate::{Error, Result, did, ensure, json, string, verification};
use reqwest::{blocking::Client, redirect::Policy as RedirectPolicy};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use url::Url;

static DNS_WORKERS: AtomicUsize = AtomicUsize::new(0);

pub struct Fetcher {
    origins: BTreeSet<String>,
    timeout: Duration,
    max_bytes: usize,
}
pub struct FetchedEntry {
    pub entry: Value,
    pub artifact: Vec<u8>,
}
impl Fetcher {
    pub fn new(origins: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut allowed = BTreeSet::new();
        for origin in origins {
            let url = https_url(&origin)?;
            ensure(
                url.path() == "/"
                    && url.query().is_none()
                    && url.origin().ascii_serialization() == origin,
                "allowlist needs bare canonical HTTPS origins",
            )?;
            allowed.insert(origin);
        }
        ensure(!allowed.is_empty(), "explicit fetch origins required")?;
        Ok(Self {
            origins: allowed,
            timeout: Duration::from_secs(15),
            max_bytes: json::MAX_JSON_BYTES,
        })
    }

    pub fn checked_url(&self, input: &str) -> Result<Url> {
        let url = https_url(input)?;
        ensure(
            self.origins.contains(&url.origin().ascii_serialization()),
            "URL origin is not explicitly allowed",
        )?;
        if let Ok(ip) = url
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
        {
            ensure(public_ip(ip), "private/reserved destination refused")?;
        }
        Ok(url)
    }

    pub fn get(&self, input: &str) -> Result<Vec<u8>> {
        let url = self.checked_url(input)?;
        let host = url
            .host_str()
            .ok_or_else(|| Error("URL host absent".into()))?;
        let started = std::time::Instant::now();
        let addresses = resolve_public(host, self.timeout)?;
        let remaining = self
            .timeout
            .checked_sub(started.elapsed())
            .ok_or_else(|| Error("DNS timeout".into()))?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .timeout(remaining)
            .connect_timeout(remaining)
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| Error("HTTP client creation failed".into()))?;
        let response = client
            .get(url)
            .header("Accept-Encoding", "identity")
            .header("Accept", "application/json, application/ai-catalog+json")
            .header("User-Agent", "aithos-catalog-signatures/0.1")
            .send()
            .map_err(|e| Error(format!("HTTPS fetch failed: {e}")))?;
        ensure(
            response.status().is_success(),
            "HTTP failure or redirect refused",
        )?;
        if let Some(encoding) = response.headers().get("content-encoding") {
            ensure(
                encoding == "identity",
                "encoded response refused; exact identity bytes required",
            )?;
        }
        ensure(
            response
                .content_length()
                .is_none_or(|n| n <= self.max_bytes as u64),
            "response exceeds size bound",
        )?;
        let mut bytes = Vec::new();
        response
            .take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("response read failed/timed out".into()))?;
        ensure(bytes.len() <= self.max_bytes, "response exceeds size bound")?;
        Ok(bytes)
    }

    pub fn entry(
        &self,
        catalog_url: &str,
        identifier: &str,
        version: Option<&str>,
    ) -> Result<FetchedEntry> {
        let catalog = json::parse(&self.get(catalog_url)?)?;
        let entry = select_entry(&catalog, identifier, version)?.clone();
        verification::validate_entry(&entry)?;
        let artifact = if let Some(data) = entry.get("data") {
            json::canonical(data)?
        } else {
            self.get(string(&entry, "url")?)?
        };
        Ok(FetchedEntry { entry, artifact })
    }

    pub fn did_document(&self, signer: &str) -> Result<Value> {
        let document = json::parse(&self.get(&did::document_url(signer)?)?)?;
        ensure(
            document.get("id").and_then(Value::as_str) == Some(signer),
            "DID id mismatch",
        )?;
        Ok(document)
    }
}

pub fn select_entry<'a>(
    catalog: &'a Value,
    identifier: &str,
    version: Option<&str>,
) -> Result<&'a Value> {
    verification::validate_catalog(catalog)?;
    let entries = catalog["entries"].as_array().expect("validated entries");
    let matches: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.get("identifier").and_then(Value::as_str) == Some(identifier)
                && version.is_none_or(|v| e.get("version").and_then(Value::as_str) == Some(v))
        })
        .collect();
    ensure(
        matches.len() == 1,
        "entry selection missing or ambiguous; specify version if needed",
    )?;
    Ok(matches[0])
}

fn https_url(input: &str) -> Result<Url> {
    ensure(
        !input.chars().any(|c| c.is_control() || c.is_whitespace()) && !input.contains('\\'),
        "invalid URL characters",
    )?;
    let url = Url::parse(input).map_err(|_| Error("invalid URL".into()))?;
    ensure(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443),
        "expected HTTPS on 443, without credentials or fragment",
    )?;
    Ok(url)
}

fn resolve_public(host: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let active = DNS_WORKERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
        if n < 8 { Some(n + 1) } else { None }
    });
    ensure(active.is_ok(), "DNS worker bound reached")?;
    let host = host.to_owned();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let spawn = std::thread::Builder::new()
        .name("catalog-dns".into())
        .spawn(move || {
            let result = (host.as_str(), 443)
                .to_socket_addrs()
                .map(|a| a.collect::<Vec<_>>());
            DNS_WORKERS.fetch_sub(1, Ordering::SeqCst);
            let _ = tx.send(result);
        });
    if spawn.is_err() {
        DNS_WORKERS.fetch_sub(1, Ordering::SeqCst);
        return Err(Error("cannot start DNS lookup".into()));
    }
    let addresses = rx
        .recv_timeout(timeout)
        .map_err(|_| Error("DNS lookup timed out".into()))?
        .map_err(|_| Error("DNS lookup failed".into()))?;
    ensure(
        !addresses.is_empty() && addresses.iter().all(|a| public_ip(a.ip())),
        "DNS resolved to private/reserved address or no address",
    )?;
    Ok(addresses)
}

/// Conservative global-unicast policy. It deliberately excludes transition,
/// documentation and special-use ranges in addition to private networks.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            ![
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 3),
            ]
            .iter()
            .any(|&(prefix, bits)| n >> (32 - bits) == prefix >> (32 - bits))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
