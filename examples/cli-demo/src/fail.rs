//! The one error type of the CLI: a message for the user and an exit status.

use std::fmt;

/// Exit status: a command-line usage error.
pub const EXIT_USAGE: u8 = 2;
/// Exit status: an I/O, network or local failure.
pub const EXIT_FAILURE: u8 = 1;
/// Exit status: the relay answered with an error status.
pub const EXIT_REFUSED: u8 = 3;
/// Exit status: a block was not accepted by this client (ADR 0026 clarification). Either it failed
/// full validation (local file or relay answer), or it is valid but fails only C1 at the local
/// floor of `get --difficulty`. The status does not say who is at fault; the message does.
pub const EXIT_INVALID: u8 = 4;

/// Why a command failed. The message never contains secret key material.
#[derive(Debug)]
pub struct Fail {
    /// Process exit status.
    pub code: u8,
    /// One or more lines for the user, without the `error: ` prefix.
    pub message: String,
}

impl Fail {
    /// A usage error (exit status 2).
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_USAGE,
            message: message.into(),
        }
    }

    /// A local, I/O or network failure (exit status 1).
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_FAILURE,
            message: message.into(),
        }
    }

    /// The relay refused the request (exit status 3).
    pub fn refused(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_REFUSED,
            message: message.into(),
        }
    }

    /// A block was not accepted: invalid, or below the local floor (exit status 4).
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_INVALID,
            message: message.into(),
        }
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Text received from a relay or read from a payload, made safe for a terminal, then cut to `max`
/// characters. Escaped (`\u{..}`, `\n`...):
/// - control characters (Unicode Cc: C0, DEL, C1), so that no terminal escape sequence reaches
///   the screen;
/// - every whitespace character but the space (tabs, line ends, U+2028, U+2029...);
/// - format characters (Unicode Cf): bidi embeddings, overrides and isolates, zero-width
///   characters, U+FEFF, and the others listed in [`is_format`], which can reorder or hide text
///   (security review 2026-11-19, L-1).
pub fn untrusted(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count >= max {
            out.push('…');
            break;
        }
        if c.is_control() || (c.is_whitespace() && c != ' ') || is_format(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Unicode general category Cf (format characters), Unicode 16. The standard library has no
/// category lookup; the list is short and stable.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

#[cfg(test)]
mod tests {
    use super::untrusted;

    #[test]
    fn escapes_control_characters_and_truncates() {
        assert_eq!(untrusted("a\u{1b}[31mb\n", 100), "a\\u{1b}[31mb\\n");
        assert_eq!(untrusted("a\u{9b}2Jb\u{7f}", 100), "a\\u{9b}2Jb\\u{7f}");
        assert_eq!(untrusted("abcdef", 3), "abc…");
    }

    #[test]
    fn escapes_bidi_invisible_and_odd_whitespace() {
        // A right-to-left override would display "evil.exe" as "exe.live".
        assert_eq!(untrusted("a\u{202E}b", 100), "a\\u{202e}b");
        for c in [
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{2060}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{E0041}',
            '\t',
            '\r',
            '\u{2028}',
            '\u{2029}',
            '\u{00A0}',
            '\u{3000}',
        ] {
            let shown = untrusted(&c.to_string(), 100);
            assert!(shown.starts_with('\\'), "{c:?} shown as {shown:?}");
            assert!(!shown.contains(c), "{c:?}");
        }
        // Ordinary text, accents and non-Latin scripts pass unchanged.
        assert_eq!(untrusted("héllo, мир, 世界 ok", 100), "héllo, мир, 世界 ok");
    }
}
