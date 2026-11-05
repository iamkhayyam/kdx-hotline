//! Local file-name hygiene for server-supplied names.
//!
//! A malicious server picks the names in its listings. Whatever we suggest in
//! the native Save dialog must be a plain basename: no directories (absolute,
//! `..`, UNC `\\host\share` — which on Windows makes the dialog probe the
//! path over SMB and leak an NTLM hash), no drive prefixes, no control or
//! bidi-override characters (which disguise extensions), no Windows-reserved
//! device names, no hidden-file leading dot.
//!
//! `kdx_client_core::safe_local_file_name` is being added in client-core as
//! well; once it lands this can delegate to it (keep these tests).

/// Longest suggested name, in bytes (well under every OS's 255 limit, leaving
/// room for a `.kdxpart` sidecar suffix).
const MAX_NAME_BYTES: usize = 200;
/// Name used when nothing usable survives sanitizing.
const FALLBACK: &str = "download";

/// Reduce a server-supplied file name to a safe local basename.
pub fn safe_local_file_name(name: &str) -> String {
    // Basename only: the last component under either separator.
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");

    let mut out = String::with_capacity(base.len());
    for c in base.chars() {
        if c.is_control() || is_invisible_format(c) {
            continue;
        }
        out.push(match c {
            ':' | '<' | '>' | '"' | '|' | '?' | '*' => '_',
            c => c,
        });
    }

    // No hidden files / `.` / `..`; Windows strips trailing dots and spaces
    // (so `x.bat.` would become `x.bat`).
    let trimmed = out
        .trim_start_matches(['.', ' '])
        .trim_end_matches(['.', ' ']);
    let mut name = truncate_keeping_extension(trimmed, MAX_NAME_BYTES);

    if name.is_empty() {
        return FALLBACK.to_string();
    }
    if is_windows_reserved(&name) {
        name.insert(0, '_');
    }
    name
}

/// Bidi overrides/embeddings/isolates and zero-width characters: invisible,
/// and able to make `exe.txt` render as `txt.exe` (or hide text entirely).
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// `CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9` — with any extension —
/// open devices on Windows instead of files.
fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end();
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let chars: Vec<char> = upper.chars().collect();
            chars.len() == 4
                && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && (chars[3].is_ascii_digit() || matches!(chars[3], '¹' | '²' | '³'))
        }
    }
}

/// Cap `name` at `max` bytes on a char boundary, preserving a short
/// extension so the file still opens with the right application.
fn truncate_keeping_extension(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_string();
    }
    let ext = name
        .rfind('.')
        .map(|i| &name[i..])
        .filter(|e| e.len() <= 16);
    let ext = ext.unwrap_or("");
    let budget = max - ext.len();
    let stem_end = name.len() - ext.len();
    let mut cut = budget.min(stem_end);
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}", &name[..cut], ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_directories() {
        assert_eq!(safe_local_file_name("../../.ssh/authorized_keys"), "authorized_keys");
        assert_eq!(safe_local_file_name("/etc/passwd"), "passwd");
        assert_eq!(safe_local_file_name("..\\x"), "x");
        assert_eq!(safe_local_file_name("C:\\x.bat"), "x.bat");
        assert_eq!(safe_local_file_name("\\\\attacker.example\\s\\song.mp3"), "song.mp3");
        assert_eq!(
            safe_local_file_name("/home/alice/.config/autostart/x.desktop"),
            "x.desktop"
        );
        assert_eq!(
            safe_local_file_name("C:\\Users\\a\\Start Menu\\Programs\\Startup\\readme.bat"),
            "readme.bat"
        );
    }

    #[test]
    fn neutralises_drive_and_stream_separators() {
        assert_eq!(safe_local_file_name("C:x.bat"), "C_x.bat");
        assert_eq!(safe_local_file_name("file.txt:evil"), "file.txt_evil");
        assert_eq!(safe_local_file_name("a<b>c|d?e*f\"g"), "a_b_c_d_e_f_g");
    }

    #[test]
    fn drops_controls_and_bidi() {
        assert_eq!(safe_local_file_name("a\0b"), "ab");
        assert_eq!(safe_local_file_name("line\nbreak\t.txt"), "linebreak.txt");
        // U+202E RIGHT-TO-LEFT OVERRIDE before "fdp.exe" renders the name as
        // "invoiceexe.pdf".
        assert_eq!(safe_local_file_name("invoice\u{202E}fdp.exe"), "invoicefdp.exe");
        assert_eq!(safe_local_file_name("\u{2067}x\u{2069}\u{200B}.txt"), "x.txt");
    }

    #[test]
    fn no_dot_names_or_trailing_dots() {
        assert_eq!(safe_local_file_name("."), FALLBACK);
        assert_eq!(safe_local_file_name(".."), FALLBACK);
        assert_eq!(safe_local_file_name(""), FALLBACK);
        assert_eq!(safe_local_file_name("/"), FALLBACK);
        assert_eq!(safe_local_file_name(".bashrc"), "bashrc");
        assert_eq!(safe_local_file_name("x. "), "x");
        assert_eq!(safe_local_file_name("x.bat."), "x.bat");
        assert_eq!(safe_local_file_name("dir/"), FALLBACK);
    }

    #[test]
    fn windows_reserved_names() {
        assert_eq!(safe_local_file_name("CON"), "_CON");
        assert_eq!(safe_local_file_name("nul.txt"), "_nul.txt");
        assert_eq!(safe_local_file_name("Com1.log"), "_Com1.log");
        assert_eq!(safe_local_file_name("lpt9"), "_lpt9");
        assert_eq!(safe_local_file_name("aux.tar.gz"), "_aux.tar.gz");
        assert_eq!(safe_local_file_name("console.txt"), "console.txt");
        assert_eq!(safe_local_file_name("COM10"), "COM10");
        assert_eq!(safe_local_file_name("com\u{b9}.txt"), "_com\u{b9}.txt");
        assert_eq!(safe_local_file_name("nullable"), "nullable");
    }

    #[test]
    fn caps_length_and_keeps_extension() {
        let long = format!("{}.mp3", "é".repeat(400));
        let out = safe_local_file_name(&long);
        assert!(out.len() <= MAX_NAME_BYTES, "{} bytes", out.len());
        assert!(out.ends_with(".mp3"));
        assert!(out.starts_with('é'));

        let no_ext = "a".repeat(1000);
        assert_eq!(safe_local_file_name(&no_ext).len(), MAX_NAME_BYTES);
    }

    #[test]
    fn ordinary_names_untouched() {
        for n in ["song.mp3", "My Document (final).pdf", "архив.zip", "日本語.txt", "a b"] {
            assert_eq!(safe_local_file_name(n), n);
        }
    }
}
