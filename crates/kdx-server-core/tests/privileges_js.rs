//! The desktop app gates its controls on the privilege bits the login result
//! carries, using constants in apps/kdx-client/dist/js/privileges.js. They
//! must match `Privileges` exactly — a renamed, renumbered, added or dropped
//! flag on either side fails here rather than silently mis-gating the UI.

use std::collections::BTreeMap;

use kdx_server_core::auth::Privileges;

const JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../apps/kdx-client/dist/js/privileges.js"
));

const BEGIN: &str = "// BEGIN privilege bits";
const END: &str = "// END privilege bits";

/// The `export const NAME = 1 << N;` lines between the markers, in order.
/// Anything else in the block (bar comments and blank lines) is an error, so
/// a constant written some other way can't slip past the comparison.
fn js_bits(src: &str) -> Vec<(String, u32)> {
    let start = src.find(BEGIN).expect("privileges.js lost its BEGIN marker");
    let end = src.find(END).expect("privileges.js lost its END marker");
    assert!(start < end, "markers out of order");
    assert_eq!(src.matches(BEGIN).count(), 1, "one BEGIN marker");
    let mut out = Vec::new();
    for line in src[start + BEGIN.len()..end].lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let parsed = line
            .strip_prefix("export const ")
            .and_then(|rest| rest.split_once(" = "))
            .and_then(|(name, value)| {
                let shift = value.strip_prefix("1 << ")?.strip_suffix(';')?.parse::<u32>().ok()?;
                let valid_name = !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_uppercase() || c == '_');
                (valid_name && shift < 32).then(|| (name.to_string(), 1u32 << shift))
            });
        out.push(parsed.unwrap_or_else(|| {
            panic!("not of the form `export const NAME = 1 << N;`: {line:?}")
        }));
    }
    out
}

fn rust_bits() -> Vec<(String, u32)> {
    Privileges::all()
        .iter_names()
        .map(|(name, flag)| (name.to_string(), flag.bits()))
        .collect()
}

#[test]
fn js_privilege_bits_match_rust() {
    let js = js_bits(JS);
    let rust = rust_bits();
    assert!(!rust.is_empty());

    let js_map: BTreeMap<_, _> = js.iter().cloned().collect();
    assert_eq!(js_map.len(), js.len(), "a privilege is defined twice in privileges.js");
    let rust_map: BTreeMap<_, _> = rust.iter().cloned().collect();
    assert_eq!(
        js_map, rust_map,
        "apps/kdx-client/dist/js/privileges.js has drifted from \
         kdx_server_core::auth::Privileges (left: JS, right: Rust)"
    );
    // Same order too, so the file reads like the Rust definition.
    assert_eq!(js, rust);
}

#[test]
fn the_parser_rejects_what_it_cannot_check() {
    let ok = format!("{BEGIN}\n// note\n\nexport const CHAT_SEND = 1 << 0;\n{END}\n");
    assert_eq!(js_bits(&ok), [("CHAT_SEND".to_string(), 1)]);
    for bad in [
        "export const CHAT_SEND = 1;",
        "export const CHAT_SEND = 0x1;",
        "export const chat_send = 1 << 0;",
        "const CHAT_SEND = 1 << 0;",
        "export const CHAT_SEND = 1 << 40;",
    ] {
        let src = format!("{BEGIN}\n{bad}\n{END}\n");
        let parsed = std::panic::catch_unwind(|| js_bits(&src));
        assert!(parsed.is_err(), "accepted {bad:?}");
    }
}
