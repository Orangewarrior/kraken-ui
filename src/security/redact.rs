//! Redaction of sensitive parameter values in WAF request/response evidence.
//!
//! The single-attack detail view (`view_waf_request`) shows the raw bytes a
//! KrakenWAF finding captured: the request URI, the full-path evidence and the
//! matched request payload. Those byte strings routinely carry credentials —
//! `password=hunter2`, `"token":"ey..."`, `senha=...` — that an auditor or an
//! operator has no operational need to read in clear.
//!
//! Only an administrator sees the original bytes. For every other role the value
//! of any parameter whose **name** matches one of the well-known sensitive words
//! in [`SENSITIVE_WORDS`] is replaced with [`REDACTED`]. The match is a
//! case-insensitive substring test over the parameter name, in many languages,
//! so `user_password`, `X-Api-Key`, `motdepasse`, `senha`, `пароль` and `密码`
//! are all caught while the surrounding structure (delimiters and quotes) is
//! preserved so the evidence stays readable.

/// Placeholder shown in place of a redacted value.
pub const REDACTED: &str = "+++++";

/// Parameter names — across many languages — whose values must never be shown to
/// a non-administrator. Matched case-insensitively as a substring of the
/// parameter name, so both the spaced (`mot de passe`) and the joined
/// (`motdepasse`, covered transitively by `passe`) spellings are caught.
pub const SENSITIVE_WORDS: &[&str] = &[
    "mot de passe",
    "passe",
    "code",
    "jeton",
    "token",
    "bearer",
    "porteur",
    "clé",
    "cle",
    "clef",
    "passwort",
    "kennwort",
    "kode",
    "träger",
    "traeger",
    "schlüssel",
    "schlussel",
    "palavra-passe",
    "palavrapasse",
    "senha",
    "código",
    "codigo",
    "portador",
    "chave",
    "contraseña",
    "contrasena",
    "clave",
    "password",
    "passwd",
    "pass",
    "key",
    "пароль",
    "код",
    "токен",
    "носитель",
    "ключ",
    "密码",
    "密碼",
    "代码",
    "代碼",
    "令牌",
    "持有者",
    "密钥",
    "密鑰",
    "钥匙",
    "鑰匙",
    "パスワード",
    "暗号",
    "コード",
    "トークン",
    "ベアラー",
    "鍵",
    "キー",
    "kata sandi",
    "katasandi",
    "sandi",
    "pembawa",
    "kunci",
];

/// Whether a parameter name names a secret. The name is trimmed of surrounding
/// quotes and whitespace, lower-cased (Unicode-aware) and tested against every
/// entry in [`SENSITIVE_WORDS`] as a substring.
fn is_sensitive_key(key: &str) -> bool {
    let key = key
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase();
    if key.is_empty() {
        return false;
    }
    SENSITIVE_WORDS.iter().any(|word| key.contains(word))
}

/// Characters that may form a parameter name token: Unicode letters and digits
/// plus the `_` and `-` joiners common in real parameter and header names.
fn is_key_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// Characters that terminate an unquoted value. Covers query strings (`&`),
/// JSON/array structure (`,`, `}`, `]`, `)`), header/line breaks and the markup
/// delimiters, so a redaction never swallows the following parameter.
fn is_value_terminator(c: char) -> bool {
    matches!(
        c,
        '&' | ';' | ',' | '\n' | '\r' | '\t' | ' ' | '"' | '\'' | '}' | ']' | ')' | '<' | '>' | '#'
    )
}

/// Replaces the value that follows a sensitive parameter's delimiter with
/// [`REDACTED`], preserving any surrounding quote, and returns the index just
/// past the consumed value. An empty value is left empty (nothing is invented).
fn redact_value(chars: &[char], mut i: usize, out: &mut String) -> usize {
    if i >= chars.len() {
        return i;
    }
    let opening = chars[i];
    if opening == '"' || opening == '\'' {
        // Quoted value: keep both quotes, replace only the bytes between them.
        out.push(opening);
        i += 1;
        let start = i;
        while i < chars.len() && chars[i] != opening {
            i += 1;
        }
        if i > start {
            out.push_str(REDACTED);
        }
        if i < chars.len() {
            out.push(chars[i]); // closing quote
            i += 1;
        }
        i
    } else {
        // Bare value: replace everything up to the next terminator.
        let start = i;
        while i < chars.len() && !is_value_terminator(chars[i]) {
            i += 1;
        }
        if i > start {
            out.push_str(REDACTED);
        }
        i
    }
}

/// Returns a copy of `input` with the value of every sensitive parameter masked.
///
/// A "parameter" is a name token immediately followed (allowing intervening
/// spaces, tabs and quotes — e.g. `"password" :`) by a `=` or `:` delimiter and
/// then a value. Non-sensitive parameters and free text pass through untouched;
/// values nested inside another value are still scanned, so a sensitive
/// parameter hidden inside a redirect URL is masked too.
pub fn redact_sensitive_values(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if !is_key_char(c) {
            out.push(c);
            i += 1;
            continue;
        }
        // Read a maximal parameter-name token.
        let start = i;
        while i < chars.len() && is_key_char(chars[i]) {
            i += 1;
        }
        let key: String = chars[start..i].iter().collect();
        // Look ahead past spaces, tabs and quotes (the JSON `"key":` case) for a
        // `=` or `:` delimiter.
        let mut j = i;
        while j < chars.len() && matches!(chars[j], ' ' | '\t' | '"' | '\'') {
            j += 1;
        }
        if j < chars.len() && (chars[j] == '=' || chars[j] == ':') && is_sensitive_key(&key) {
            // Emit the name, the gap and the delimiter verbatim, then mask the
            // value (preserving leading whitespace after the delimiter).
            out.push_str(&key);
            out.extend(chars[i..=j].iter());
            i = j + 1;
            while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                out.push(chars[i]);
                i += 1;
            }
            i = redact_value(&chars, i, &mut out);
        } else {
            // Not a sensitive parameter: emit the name and keep scanning. The gap
            // characters are reprocessed normally (and may start a nested match).
            out.push_str(&key);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{REDACTED, is_sensitive_key, redact_sensitive_values};

    #[test]
    fn masks_form_urlencoded_passwords_and_keeps_other_params() {
        assert_eq!(
            redact_sensitive_values("user=alice&password=hunter2&page=3"),
            "user=alice&password=+++++&page=3"
        );
    }

    #[test]
    fn masks_json_style_quoted_values() {
        assert_eq!(
            redact_sensitive_values(r#"{"token":"ey.secret","keep":"me"}"#),
            r#"{"token":"+++++","keep":"me"}"#
        );
    }

    #[test]
    fn masks_spaced_json_keys_and_preserves_whitespace() {
        assert_eq!(
            redact_sensitive_values(r#"{ "senha" : "s3cr3t" }"#),
            r#"{ "senha" : "+++++" }"#
        );
    }

    #[test]
    fn masks_values_in_many_languages() {
        assert_eq!(redact_sensitive_values("jeton=abc"), "jeton=+++++");
        assert_eq!(
            redact_sensitive_values("contraseña=abc"),
            "contraseña=+++++"
        );
        assert_eq!(redact_sensitive_values("пароль=abc"), "пароль=+++++");
        assert_eq!(redact_sensitive_values("密码=abc"), "密码=+++++");
        assert_eq!(redact_sensitive_values("kunci=abc"), "kunci=+++++");
    }

    #[test]
    fn matches_compound_names_containing_a_sensitive_word() {
        assert_eq!(
            redact_sensitive_values("X-Api-Key=deadbeef"),
            "X-Api-Key=+++++"
        );
        assert_eq!(
            redact_sensitive_values("user_password=p"),
            "user_password=+++++"
        );
        // The joined French spelling is caught transitively by `passe`.
        assert_eq!(redact_sensitive_values("motdepasse=p"), "motdepasse=+++++");
    }

    #[test]
    fn masks_a_sensitive_parameter_nested_in_a_value() {
        assert_eq!(
            redact_sensitive_values("next=/login?token=abc&ok=1"),
            "next=/login?token=+++++&ok=1"
        );
    }

    #[test]
    fn leaves_plain_text_and_non_sensitive_params_untouched() {
        let input = "GET /search?q=cats HTTP/1.1\nHost: example.test\nlimit=20";
        assert_eq!(redact_sensitive_values(input), input);
    }

    #[test]
    fn leaves_an_empty_value_empty() {
        assert_eq!(
            redact_sensitive_values("password=&next=x"),
            "password=&next=x"
        );
    }

    #[test]
    fn is_idempotent_so_the_placeholder_survives_a_second_pass() {
        let once = redact_sensitive_values("token=secret");
        assert_eq!(once, format!("token={REDACTED}"));
        assert_eq!(redact_sensitive_values(&once), once);
    }

    #[test]
    fn key_classifier_is_case_insensitive_and_quote_tolerant() {
        assert!(is_sensitive_key("PASSWORD"));
        assert!(is_sensitive_key("\"Token\""));
        assert!(!is_sensitive_key("username"));
        assert!(!is_sensitive_key(""));
    }
}
