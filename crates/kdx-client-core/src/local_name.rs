//! Turning server-supplied file names into something safe to offer as a
//! local file name (e.g. a save dialog's default). A server controls every
//! name in a listing, so a name may be a path (`../../.ssh/authorized_keys`,
//! `C:\Users\…\Startup\x.bat`), a UNC share (`\\attacker\s\x`, which makes
//! Windows open an SMB session just by stat-ing it), a reserved device
//! (`CON`, `nul.txt`) or carry control/bidi characters that disguise its
//! extension.

/// Longest name we return, in bytes: comfortably within the usual 255-byte
/// file-name limit. (Nothing is appended to a download's name any more —
/// partials live in the client's data directory, and the only file ever
/// created beside a destination is a fixed-length 40-byte temp name during
/// a cross-filesystem copy.)
const MAX_NAME_BYTES: usize = 200;

/// Used when nothing usable is left of the server's name.
const FALLBACK_NAME: &str = "download";

/// Windows device names, reserved with any extension and in any case.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "COM0", "COM1", "COM2", "COM3",
    "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT0", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

/// Characters that are stripped outright: invisible formatting that can
/// reorder or hide parts of a name (bidi overrides/isolates, marks, BOM,
/// zero-width space, line/paragraph separators).
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Reduce a server-supplied name to a single, harmless local file name:
///
/// - only the last path component is kept (`/` and `\` both separate, so
///   absolute paths, `..` traversal, drive paths and UNC shares collapse to
///   their basename);
/// - NUL, control characters and invisible bidi/formatting characters are
///   removed; characters Windows forbids (`<>:"|?*`) become `_`;
/// - leading whitespace and trailing dots/spaces are trimmed, and `.`/`..`
///   or an empty result become `download`;
/// - Windows reserved device names (`CON`, `nul.txt`, `COM1.log`, …) are
///   prefixed with `_`;
/// - the result is capped at 200 bytes, keeping a short extension.
///
/// Apply it to every name that came from the server before it touches the
/// local filesystem or a file dialog.
pub fn safe_local_file_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or("");

    let cleaned: String = base
        .chars()
        .filter(|&c| !c.is_control() && !is_invisible(c))
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            other => other,
        })
        .collect();

    let mut out = cleaned.trim_start().trim_end_matches(['.', ' ']).to_string();
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return FALLBACK_NAME.to_string();
    }

    // Windows matches device names on the part before the first dot, with
    // trailing spaces ignored.
    let stem = out.split('.').next().unwrap_or("").trim_end();
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        out.insert(0, '_');
    }

    cap_length(out)
}

/// Truncate to `MAX_NAME_BYTES` on a char boundary, preserving a short
/// extension so the file keeps its type.
fn cap_length(name: String) -> String {
    if name.len() <= MAX_NAME_BYTES {
        return name;
    }
    let ext = name
        .rfind('.')
        .filter(|&i| i > 0 && name.len() - i <= 16)
        .map(|i| name[i..].to_string())
        .unwrap_or_default();
    let mut cut = MAX_NAME_BYTES - ext.len();
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = name[..cut].trim_end_matches(['.', ' ']).to_string();
    if out.is_empty() {
        out = FALLBACK_NAME.to_string();
    }
    out.push_str(&ext);
    out
}

#[cfg(test)]
mod tests {
    use super::safe_local_file_name as safe;

    #[test]
    fn path_components_are_stripped() {
        assert_eq!(safe("../../.ssh/authorized_keys"), "authorized_keys");
        assert_eq!(safe("/etc/passwd"), "passwd");
        assert_eq!(safe("C:\\x.bat"), "x.bat");
        assert_eq!(safe("..\\x"), "x");
        assert_eq!(safe("\\\\host\\s\\x"), "x");
        assert_eq!(safe("\\\\attacker.example\\s\\song.mp3"), "song.mp3");
        assert_eq!(
            safe("C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.bat"),
            "x.bat"
        );
        assert_eq!(safe("/home/alice/.config/autostart/x.desktop"), "x.desktop");
        assert_eq!(safe("dir/"), "dir");
        // Drive-relative and alternate-data-stream forms lose their colon.
        assert_eq!(safe("C:x.bat"), "C_x.bat");
        assert_eq!(safe("notes.txt:Zone.Identifier"), "notes.txt_Zone.Identifier");
    }

    #[test]
    fn dot_names_and_empties_fall_back() {
        assert_eq!(safe("."), "download");
        assert_eq!(safe(".."), "download");
        assert_eq!(safe("..."), "download");
        assert_eq!(safe(""), "download");
        assert_eq!(safe("/"), "download");
        assert_eq!(safe("  "), "download");
        assert_eq!(safe("../.."), "download");
        // Ordinary dotfiles are kept.
        assert_eq!(safe(".gitignore"), ".gitignore");
    }

    #[test]
    fn control_and_bidi_characters_are_removed() {
        assert_eq!(safe("a\0b"), "ab");
        assert_eq!(safe("line\nbreak\r.txt"), "linebreak.txt");
        assert_eq!(safe("tab\there\x7f"), "tabhere");
        // A right-to-left override makes "invoice<RLO>fdp.exe" display as
        // "invoiceexe.pdf".
        assert_eq!(safe("invoice\u{202E}fdp.exe"), "invoicefdp.exe");
        assert_eq!(safe("a\u{2066}b\u{2069}\u{200F}\u{FEFF}c"), "abc");
        assert_eq!(safe("what?<>|*\".txt"), "what______.txt");
    }

    #[test]
    fn trailing_dots_and_spaces_are_trimmed() {
        assert_eq!(safe("x. "), "x");
        assert_eq!(safe("x.bat. . "), "x.bat");
        assert_eq!(safe("  lead.txt"), "lead.txt");
    }

    #[test]
    fn windows_reserved_names_are_mapped() {
        assert_eq!(safe("CON"), "_CON");
        assert_eq!(safe("con"), "_con");
        assert_eq!(safe("nul.txt"), "_nul.txt");
        assert_eq!(safe("COM1.log"), "_COM1.log");
        assert_eq!(safe("lpt9.tar.gz"), "_lpt9.tar.gz");
        assert_eq!(safe("aux .txt"), "_aux .txt");
        assert_eq!(safe("conin$"), "_conin$");
        assert_eq!(safe("COM¹"), "_COM¹");
        // Not reserved: longer stems.
        assert_eq!(safe("console.txt"), "console.txt");
        assert_eq!(safe("COM10"), "COM10");
    }

    #[test]
    fn length_is_capped_on_a_char_boundary() {
        let long = format!("{}.mp3", "é".repeat(400));
        let out = safe(&long);
        assert!(out.len() <= 200);
        assert!(out.ends_with(".mp3"));
        assert!(out.starts_with('é'));
        let no_ext = "x".repeat(1000);
        assert_eq!(safe(&no_ext).len(), 200);
    }

    #[test]
    fn ordinary_names_pass_through() {
        assert_eq!(safe("song.mp3"), "song.mp3");
        assert_eq!(safe("Ünïcødé 名前.txt"), "Ünïcødé 名前.txt");
        assert_eq!(safe("a-b_c (1).tar.gz"), "a-b_c (1).tar.gz");
    }
}
