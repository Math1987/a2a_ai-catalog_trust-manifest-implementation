#![cfg(feature = "http")]
use aithos_catalog_signatures::fetch::{Fetcher, public_ip, select_entry};
use serde_json::json;

#[test]
fn unsafe_origins_and_url_forms_are_rejected_before_io() {
    let fetcher = Fetcher::new(["https://catalog.example".into()]).unwrap();
    for url in [
        "http://catalog.example/x",
        "https://catalog.example:8443/x",
        "https://user:secret@catalog.example/x",
        "https://catalog.example/x#fragment",
        "https://other.example/x",
        "https://127.0.0.1/",
        "https://catalog.example\\@evil.example/",
    ] {
        assert!(fetcher.checked_url(url).is_err(), "{url}");
    }
    assert!(
        fetcher
            .checked_url("https://catalog.example/catalog.json")
            .is_ok()
    );
    assert!(Fetcher::new(["https://catalog.example/path".into()]).is_err());
    let local = Fetcher::new(["https://127.0.0.1".into()]).unwrap();
    assert!(local.checked_url("https://127.0.0.1/").is_err());
}

#[test]
fn private_special_and_transition_addresses_are_blocked() {
    for ip in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "2002:7f00:1::",
        "64:ff9b::7f00:1",
    ] {
        assert!(!public_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
        assert!(public_ip(ip.parse().unwrap()));
    }
}

#[test]
fn catalog_selection_is_exact_and_rejects_ambiguity() {
    let mut catalog = json!({"specVersion":"1.0","entries":[{"identifier":"urn:air:example.com:agent:test","version":"1"},
        {"identifier":"urn:air:example.com:agent:test","version":"2"}]});
    let id = "urn:air:example.com:agent:test";
    assert!(select_entry(&catalog, id, None).is_err());
    assert_eq!(
        select_entry(&catalog, id, Some("2")).unwrap()["version"],
        "2"
    );
    assert!(select_entry(&catalog, "missing", None).is_err());
    catalog["entries"][1]["version"] = "1".into();
    assert!(select_entry(&catalog, id, Some("1")).is_err());
}
