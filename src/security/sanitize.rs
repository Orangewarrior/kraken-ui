use std::collections::HashSet;

use ammonia::Builder;
use memchr::memchr;

pub fn plain_text(input: &str) -> String {
    let allowed_tags = HashSet::new();
    Builder::default()
        .tags(allowed_tags)
        .clean(input)
        .to_string()
        .trim()
        .to_owned()
}

pub fn secret_has_rejected_markup(input: &str) -> bool {
    let bytes = input.as_bytes();
    let has_markup_delimiter = memchr(b'<', bytes).is_some() || memchr(b'>', bytes).is_some();
    has_markup_delimiter && plain_text(input) != input
}

/// Escapes the SQL `LIKE` metacharacters (`\`, `%`, `_`) so a search term is
/// matched literally. Pair this with a `LIKE ... ESCAPE '\'` clause. Without it,
/// a user-supplied `%` or `_` would silently act as a wildcard and broaden the
/// search.
pub fn escape_like(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{plain_text, secret_has_rejected_markup};

    #[test]
    fn removes_markup_from_untrusted_text() {
        assert_eq!(plain_text("  <script>alert(1)</script>admin  "), "admin");
    }

    #[test]
    fn accepts_ampersand_in_a_secret_without_treating_it_as_markup() {
        assert!(!secret_has_rejected_markup("Long&Random#Pass9"));
    }

    #[test]
    fn rejects_markup_in_a_secret() {
        assert!(secret_has_rejected_markup("<b>LongRandomPass9!</b>"));
    }

    #[test]
    fn escapes_like_metacharacters() {
        assert_eq!(super::escape_like("100%_\\x"), "100\\%\\_\\\\x");
        assert_eq!(super::escape_like("plain"), "plain");
    }
}
