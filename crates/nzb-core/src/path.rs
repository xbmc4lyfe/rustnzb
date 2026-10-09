//! Path validation shared by download and post-processing boundaries.

use std::path::{Path, PathBuf};

/// Join an untrusted archive or API supplied relative name beneath `root`.
/// Backslashes are treated as separators on every platform.
pub fn safe_join(root: &Path, name: &str) -> Option<PathBuf> {
    let normalized = name.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.as_bytes().get(1) == Some(&b':')
        || normalized.chars().any(char::is_control)
    {
        return None;
    }

    let mut output = root.to_path_buf();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            component => output.push(component),
        }
    }
    output.starts_with(root).then_some(output)
}

/// Whether `ch` is an invisible bidirectional or zero-width formatting
/// character that must not survive into a job or file name.
///
/// This covers the bidi embeddings and overrides (U+202A..=U+202E), the bidi
/// isolates (U+2066..=U+2069), the directional marks LRM, RLM and ALM
/// (U+200E, U+200F, U+061C), ZERO WIDTH SPACE (U+200B) and the byte order
/// mark / ZERO WIDTH NO-BREAK SPACE (U+FEFF). An RTL override lets a name
/// such as `clip\u{202E}4pm.exe` display as `clipexe.mp4`.
///
/// It deliberately does not cover every Unicode `Cf` character: ZERO WIDTH
/// JOINER (U+200D) and ZERO WIDTH NON-JOINER (U+200C) are required by emoji
/// sequences (family, flag and profession emoji) and by scripts such as
/// Persian and the Indic scripts, so stripping them would corrupt
/// legitimate names.
pub(crate) fn is_bidi_or_invisible_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{200B}'
            | '\u{FEFF}'
    )
}

/// Validate a user supplied directory or category component.
/// These values are intentionally a single path component.
pub fn safe_component(value: &str) -> Option<&str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value.chars().any(is_bidi_or_invisible_control)
    {
        return None;
    }
    Some(value)
}

/// Maximum length, in bytes, of a sanitized job name. Leaves headroom under
/// the common 255-byte `NAME_MAX` for suffixes such as `.1` or `_UNPACK_`.
pub const MAX_JOB_NAME_BYTES: usize = 240;

/// Job name used when sanitization leaves nothing usable.
pub const UNNAMED_JOB: &str = "unnamed";

/// Turn an untrusted job name (usually an NZB filename stem) into a single
/// directory name that is valid on Linux, macOS, Windows and SMB shares.
///
/// Rules, applied in order:
/// - Unicode NFC normalization.
/// - `:` becomes `-`, or ` -` when it is followed by whitespace, so
///   `Star Trek: Discovery` reads `Star Trek - Discovery`.
/// - The other Windows-illegal characters `< > " / \ | ? *` and control
///   characters become `_`.
/// - Bidi controls and zero-width spaces (U+202A-202E, U+2066-2069,
///   U+200E, U+200F, U+061C, U+200B, U+FEFF) are removed. ZWJ and ZWNJ
///   are kept because emoji sequences and some scripts need them.
/// - Leading and trailing whitespace and dots are trimmed.
/// - Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
///   `LPT1`-`LPT9`, case-insensitive, with or without an extension) get a
///   `_` prefix.
/// - The result is truncated to [`MAX_JOB_NAME_BYTES`] on a char boundary.
/// - An empty result becomes [`UNNAMED_JOB`].
///
/// The output always passes [`safe_component`] and [`safe_join`], and
/// sanitizing an already sanitized name returns it unchanged.
pub fn sanitize_job_name(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    let normalized: String = name.nfc().collect();
    let mut replaced = String::with_capacity(normalized.len());
    let mut chars = normalized.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ':' => {
                let spaced = chars.peek().is_some_and(|next| next.is_whitespace())
                    && !replaced.ends_with(char::is_whitespace);
                replaced.push_str(if spaced { " -" } else { "-" });
            }
            '<' | '>' | '"' | '/' | '\\' | '|' | '?' | '*' => replaced.push('_'),
            c if c.is_control() => replaced.push('_'),
            c if is_bidi_or_invisible_control(c) => {}
            c => replaced.push(c),
        }
    }

    let trim = |s: &str| -> String {
        s.trim_matches(|c: char| c.is_whitespace() || c == '.')
            .to_string()
    };
    let mut out = trim(&replaced);
    if out.is_empty() {
        return UNNAMED_JOB.to_string();
    }
    if is_windows_reserved_name(&out) {
        out.insert(0, '_');
    }
    if out.len() > MAX_JOB_NAME_BYTES {
        let mut end = MAX_JOB_NAME_BYTES;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        // Truncation may expose a trailing dot or space; the first char is
        // neither, so this can never empty the name.
        out = trim(&out);
    }
    out
}

/// Whether `name` is a Windows reserved device name. Windows ignores the
/// extension and trailing spaces, so `con.txt` and `NUL .x` count too.
fn is_windows_reserved_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let bytes = upper.as_bytes();
            bytes.len() == 4
                && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && (b'1'..=b'9').contains(&bytes[3])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_cross_platform_escape_paths() {
        let root = Path::new("/tmp/job");
        assert!(safe_join(root, "folder/file.txt").is_some());
        for path in ["../outside", r"..\outside", "/etc/passwd", r"C:\temp"] {
            assert!(safe_join(root, path).is_none(), "{path}");
        }
        assert!(safe_component("movies").is_some());
        assert!(safe_component("../outside").is_none());
        assert!(safe_component(r"movies\tv").is_none());
    }

    #[test]
    fn sanitize_job_name_replaces_windows_illegal_characters() {
        assert_eq!(sanitize_job_name("a:b*c?d"), "a-b_c_d");
        assert_eq!(
            sanitize_job_name("Star Trek: Discovery"),
            "Star Trek - Discovery"
        );
        assert_eq!(sanitize_job_name(r#"x<y>z"q|r"#), "x_y_z_q_r");
        assert_eq!(sanitize_job_name("tab\there"), "tab_here");
        assert_eq!(sanitize_job_name("C:"), "C-");
    }

    #[test]
    fn sanitize_job_name_neutralizes_traversal_and_separators() {
        assert_eq!(sanitize_job_name("."), UNNAMED_JOB);
        assert_eq!(sanitize_job_name(".."), UNNAMED_JOB);
        assert_eq!(sanitize_job_name(""), UNNAMED_JOB);
        assert_eq!(sanitize_job_name(" . "), UNNAMED_JOB);
        assert_eq!(sanitize_job_name("../etc/passwd"), "_etc_passwd");
        assert_eq!(sanitize_job_name(r"..\outside"), "_outside");
        assert_eq!(sanitize_job_name("/abs"), "_abs");
    }

    #[test]
    fn sanitize_job_name_trims_dots_and_whitespace() {
        assert_eq!(sanitize_job_name("Trailing.Dot."), "Trailing.Dot");
        assert_eq!(
            sanitize_job_name(" lead and trail space "),
            "lead and trail space"
        );
        assert_eq!(sanitize_job_name(".hidden"), "hidden");
        assert_eq!(sanitize_job_name("Show.S01E01.1080p"), "Show.S01E01.1080p");
    }

    #[test]
    fn sanitize_job_name_prefixes_windows_reserved_names() {
        for (input, expected) in [
            ("CON", "_CON"),
            ("con", "_con"),
            ("Nul.txt", "_Nul.txt"),
            ("aux.tar.gz", "_aux.tar.gz"),
            ("COM1", "_COM1"),
            ("lpt9.log", "_lpt9.log"),
            ("NUL .x", "_NUL .x"),
        ] {
            assert_eq!(sanitize_job_name(input), expected, "{input}");
        }
        for kept in ["CONSOLE", "COM0", "COM10", "LPT", "Conan", "NULL.x"] {
            assert_eq!(sanitize_job_name(kept), kept);
        }
    }

    #[test]
    fn sanitize_job_name_truncates_on_a_char_boundary() {
        let long = "x".repeat(300);
        assert_eq!(sanitize_job_name(&long), "x".repeat(MAX_JOB_NAME_BYTES));

        // 'é' is two bytes; 239 ASCII bytes leave a split char at 240.
        let multibyte = format!("{}{}", "a".repeat(239), "é".repeat(10));
        let out = sanitize_job_name(&multibyte);
        assert!(out.len() <= MAX_JOB_NAME_BYTES);
        assert_eq!(out, "a".repeat(239));

        // A dot exposed by truncation is trimmed again.
        let dotted = format!("{}. tail", "b".repeat(MAX_JOB_NAME_BYTES - 1));
        assert_eq!(
            sanitize_job_name(&dotted),
            "b".repeat(MAX_JOB_NAME_BYTES - 1)
        );
    }

    #[test]
    fn sanitize_job_name_output_is_safe_and_idempotent() {
        let root = Path::new("/tmp/complete");
        for input in [
            "a:b*c?d",
            "..",
            ".",
            "../x",
            "C:\\temp",
            "CON",
            " x. ",
            "\u{0}nul",
            "café",
            "Star Trek: Discovery",
        ] {
            let once = sanitize_job_name(input);
            assert!(safe_component(&once).is_some(), "{input:?} -> {once:?}");
            assert!(safe_join(root, &once).is_some(), "{input:?} -> {once:?}");
            assert_eq!(sanitize_job_name(&once), once, "{input:?}");
        }
        // NFD input is normalized to NFC.
        assert_eq!(sanitize_job_name("cafe\u{0301}"), "caf\u{00E9}");
    }
    #[test]
    fn sanitize_job_name_strips_bidi_and_invisible_controls() {
        // RTL override spoofing: "clip\u{202E}4pm.exe" displays as "clipexe.mp4".
        assert_eq!(sanitize_job_name("clip\u{202E}4pm.exe"), "clip4pm.exe");
        for ch in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}', '\u{061C}', '\u{200B}', '\u{FEFF}',
        ] {
            let input = format!("a{ch}b");
            assert_eq!(sanitize_job_name(&input), "ab", "{:04X}", ch as u32);
        }
        // A name made only of invisible characters falls back to the default.
        assert_eq!(sanitize_job_name("\u{202E}\u{FEFF}"), UNNAMED_JOB);
    }

    #[test]
    fn sanitize_job_name_keeps_joiners_cjk_and_accents() {
        // ZWJ emoji sequence (family) and ZWNJ (Persian) must survive.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert_eq!(sanitize_job_name(family), family);
        let persian = "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}";
        assert_eq!(sanitize_job_name(persian), persian);
        for text in ["進撃の巨人 第1話", "Amélie Poulain", "Ñandú über straße"] {
            assert_eq!(sanitize_job_name(text), text);
        }
    }

    #[test]
    fn safe_component_rejects_bidi_controls() {
        assert!(safe_component("movies\u{202E}vka").is_none());
        assert!(safe_component("\u{2066}tv\u{2069}").is_none());
        assert!(safe_component("tv\u{200F}").is_none());
        assert!(safe_component("tv\u{FEFF}").is_none());
        assert!(safe_component("\u{1F468}\u{200D}\u{1F469}").is_some());
        assert!(safe_component("映画").is_some());
    }
}
