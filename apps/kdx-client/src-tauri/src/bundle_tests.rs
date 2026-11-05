//! The macOS bundle's sandbox configuration, checked on every platform: it
//! only takes effect when the app is code-signed on macOS, so a regression
//! here would otherwise surface only in a release build.

use std::path::Path;

const ENTITLEMENTS: &str = include_str!("../entitlements.plist");
const MIGRATION: &str = include_str!("../container-migration.plist");
const CONF: &str = include_str!("../tauri.conf.json");

/// `plist` without its `<!-- … -->` comments.
fn strip_comments(plist: &str) -> String {
    let mut out = String::new();
    let mut rest = plist;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find("-->").expect("unterminated comment");
        rest = &rest[start + end + 3..];
    }
    out.push_str(rest);
    out
}

/// The `<key>…</key>` / value pairs of a flat entitlements dict, values as
/// written (`<true/>`, `<false/>`, …).
fn entries(plist: &str) -> Vec<(String, String)> {
    let body = strip_comments(plist);
    let mut out = Vec::new();
    let mut rest = body.as_str();
    while let Some(start) = rest.find("<key>") {
        let after = &rest[start + 5..];
        let end = after.find("</key>").expect("unterminated key");
        let key = after[..end].trim().to_string();
        let value_part = after[end + 6..].trim_start();
        let value_end = value_part.find('>').expect("missing value") + 1;
        out.push((key, value_part[..value_end].to_string()));
        rest = &value_part[value_end..];
    }
    out
}

#[test]
fn the_app_is_sandboxed_with_only_what_it_needs() {
    let mut got = entries(ENTITLEMENTS);
    got.sort();
    let mut want: Vec<(String, String)> = [
        "com.apple.security.app-sandbox",
        // Outbound TCP to KDX servers.
        "com.apple.security.network.client",
        // The file picked in the native Open/Save dialog, nothing else.
        "com.apple.security.files.user-selected.read-write",
    ]
    .iter()
    .map(|k| (k.to_string(), "<true/>".to_string()))
    .collect();
    want.sort();
    assert_eq!(got, want, "entitlements changed: review docs/packaging.html first");
}

#[test]
fn the_bundle_applies_the_entitlements_and_migration_manifest() {
    let conf: serde_json::Value = serde_json::from_str(CONF).unwrap();
    let mac = &conf["bundle"]["macOS"];
    assert_eq!(mac["entitlements"], "entitlements.plist");
    // Entitlements (the sandbox) only apply to a signed bundle: every build
    // is at least ad-hoc signed; APPLE_SIGNING_IDENTITY overrides this with a
    // Developer ID for distribution.
    assert_eq!(mac["signingIdentity"], "-");
    assert_eq!(mac["hardenedRuntime"], true, "notarization requires the hardened runtime");
    let source = mac["files"]["Resources/container-migration.plist"]
        .as_str()
        .expect("the container migration manifest is bundled");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(dir.join(source).is_file(), "{source} is missing");
    assert!(dir.join(mac["entitlements"].as_str().unwrap()).is_file());
}

/// The migration manifest moves the unsandboxed build's state into the
/// container: it must name the directories of this bundle identifier
/// (Tauri's app_data_dir and the webview's storage).
#[test]
fn the_migration_manifest_matches_the_bundle_identifier() {
    let conf: serde_json::Value = serde_json::from_str(CONF).unwrap();
    let id = conf["identifier"].as_str().unwrap();
    let body = strip_comments(MIGRATION);
    for path in [
        format!("<string>${{ApplicationSupport}}/{id}</string>"),
        format!("<string>${{Library}}/WebKit/{id}</string>"),
    ] {
        assert!(body.contains(&path), "container-migration.plist lacks {path}");
    }
    assert!(body.contains("<key>Move</key>"));
}
