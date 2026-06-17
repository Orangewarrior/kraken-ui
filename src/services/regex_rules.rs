//! Regex rule-list domain logic: the closed allowlist of editable rule files and
//! the per-context validation that turns editor text into the exact body posted
//! to KrakenWAF's `/rule/control/regex/update/<name>` endpoint.
//!
//! Each rule list has a different on-disk shape (a JSON regex bundle, a JSON
//! keyword bundle, or a line-delimited text file), so the validation has to adapt
//! to the context. A small **factory** ([`codec_for`]) maps a [`RegexRuleList`]
//! to the [`RuleCodec`] that knows how to validate that shape and produce the
//! wire body, keeping the controller free of any per-format branching.
//!
//! No content ever reaches the WAF without passing the matching codec first: a
//! broken JSON document, an empty rule file, or a rule element missing a required
//! field is rejected here with a message the operator can act on.

use serde_json::{Value, json};

/// Required fields on every element of a regex rule bundle, mirroring the shape
/// KrakenWAF documents (`docs/rule_management.md`). A rule missing any of these
/// is rejected before it can reach the WAF.
const REQUIRED_RULE_FIELDS: [&str; 10] = [
    "enable",
    "http_action",
    "title",
    "severity",
    "cwe",
    "description",
    "url",
    "rule_match",
    "id",
    "score",
];

/// The closed allowlist of rule lists the console can view and edit. Anything
/// outside this set is refused before a request is built, so a forged rule name
/// can never become part of the upstream path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegexRuleList {
    BodyRegex,
    PathRegex,
    HeaderRegex,
    VectorscanList,
    Scanners,
}

impl RegexRuleList {
    /// Every selectable rule list, in the order shown in the editor's select box.
    pub const ALL: [RegexRuleList; 5] = [
        RegexRuleList::BodyRegex,
        RegexRuleList::PathRegex,
        RegexRuleList::HeaderRegex,
        RegexRuleList::VectorscanList,
        RegexRuleList::Scanners,
    ];

    /// Resolves the wire name (`body_regex`, ...) to a known rule list, or `None`
    /// when it is not on the allowlist.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "body_regex" => Some(RegexRuleList::BodyRegex),
            "path_regex" => Some(RegexRuleList::PathRegex),
            "header_regex" => Some(RegexRuleList::HeaderRegex),
            "vectorscan_list" => Some(RegexRuleList::VectorscanList),
            "scanners" => Some(RegexRuleList::Scanners),
            _ => None,
        }
    }

    /// The canonical wire name used in the WAF view body and update path.
    pub fn as_str(&self) -> &'static str {
        match self {
            RegexRuleList::BodyRegex => "body_regex",
            RegexRuleList::PathRegex => "path_regex",
            RegexRuleList::HeaderRegex => "header_regex",
            RegexRuleList::VectorscanList => "vectorscan_list",
            RegexRuleList::Scanners => "scanners",
        }
    }

    /// The ACE syntax-highlighting mode for this list: most lists are JSON, the
    /// scanner allowlist is line-delimited plain text.
    pub fn editor_mode(&self) -> &'static str {
        match self {
            RegexRuleList::Scanners => "ace/mode/text",
            _ => "ace/mode/json",
        }
    }
}

/// A validation failure, carrying enough detail for the operator to fix the
/// content. The [`std::fmt::Display`] text is what the UI surfaces.
#[derive(Debug, PartialEq, Eq)]
pub enum RuleValidationError {
    /// The editor was submitted empty (or whitespace only).
    Empty,
    /// The content is not valid JSON; carries the parser's message.
    InvalidJson(String),
    /// The top-level JSON value is not an object.
    NotAnObject,
    /// The `rules` array is absent or not an array.
    MissingRulesArray,
    /// The `rules` array is present but empty.
    EmptyRules,
    /// A `rules` element is not a JSON object.
    RuleNotObject { index: usize },
    /// A `rules` element is missing a required field.
    MissingField { index: usize, field: &'static str },
    /// A `rules` element has a required field of the wrong type / empty value.
    InvalidField { index: usize, field: &'static str },
}

impl std::fmt::Display for RuleValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleValidationError::Empty => {
                write!(formatter, "The rule file cannot be empty.")
            }
            RuleValidationError::InvalidJson(detail) => {
                write!(formatter, "The rule content is not valid JSON: {detail}.")
            }
            RuleValidationError::NotAnObject => {
                write!(formatter, "The rule content must be a JSON object.")
            }
            RuleValidationError::MissingRulesArray => write!(
                formatter,
                "The rule content must contain a \"rules\" array."
            ),
            RuleValidationError::EmptyRules => {
                write!(formatter, "The \"rules\" array cannot be empty.")
            }
            RuleValidationError::RuleNotObject { index } => {
                write!(formatter, "Rule #{} must be a JSON object.", index + 1)
            }
            RuleValidationError::MissingField { index, field } => write!(
                formatter,
                "Rule #{} is missing the required \"{field}\" field.",
                index + 1
            ),
            RuleValidationError::InvalidField { index, field } => write!(
                formatter,
                "Rule #{} has an invalid \"{field}\" value.",
                index + 1
            ),
        }
    }
}

/// Validates editor content for one rule-list shape and renders the exact bytes
/// to POST upstream. Implementations are selected by [`codec_for`].
pub trait RuleCodec {
    /// Validates `content` and returns the raw request body for the WAF update.
    fn build_update_body(&self, content: &str) -> Result<Vec<u8>, RuleValidationError>;
}

/// **Factory**: returns the codec that matches a rule list's on-disk shape.
pub fn codec_for(list: RegexRuleList) -> Box<dyn RuleCodec> {
    match list {
        RegexRuleList::BodyRegex | RegexRuleList::PathRegex | RegexRuleList::HeaderRegex => {
            Box::new(RegexBundleCodec)
        }
        RegexRuleList::VectorscanList => Box::new(KeywordBundleCodec),
        RegexRuleList::Scanners => Box::new(LineListCodec),
    }
}

/// Parses content into a JSON object and returns a reference to a non-empty
/// `rules` array, the shared front half of both JSON-bundle codecs.
fn parse_rules_array(content: &str) -> Result<(Value, usize), RuleValidationError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(RuleValidationError::Empty);
    }
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(value) => value,
        Err(error) => return Err(RuleValidationError::InvalidJson(error.to_string())),
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => return Err(RuleValidationError::NotAnObject),
    };
    let rules = match object.get("rules").and_then(Value::as_array) {
        Some(rules) => rules,
        None => return Err(RuleValidationError::MissingRulesArray),
    };
    if rules.is_empty() {
        return Err(RuleValidationError::EmptyRules);
    }
    let count = rules.len();
    Ok((value, count))
}

/// Codec for the regex rule bundles (`body_regex`, `path_regex`, `header_regex`).
/// Validates that every rule element carries the documented required fields, then
/// forwards the operator's exact JSON so their formatting is preserved on disk.
struct RegexBundleCodec;

impl RuleCodec for RegexBundleCodec {
    fn build_update_body(&self, content: &str) -> Result<Vec<u8>, RuleValidationError> {
        let (value, _count) = parse_rules_array(content)?;
        // Safe: parse_rules_array guarantees an object with a non-empty array.
        let rules = match value.get("rules").and_then(Value::as_array) {
            Some(rules) => rules,
            None => return Err(RuleValidationError::MissingRulesArray),
        };
        for (index, rule) in rules.iter().enumerate() {
            let object = match rule.as_object() {
                Some(object) => object,
                None => return Err(RuleValidationError::RuleNotObject { index }),
            };
            for field in REQUIRED_RULE_FIELDS {
                match object.get(field) {
                    None => return Err(RuleValidationError::MissingField { index, field }),
                    Some(Value::Null) => {
                        return Err(RuleValidationError::InvalidField { index, field });
                    }
                    Some(_) => {}
                }
            }
            // The regex itself must be a non-empty string: an empty pattern can
            // never have been the operator's intent and would weaken the rule.
            match object.get("rule_match") {
                Some(Value::String(pattern)) if !pattern.is_empty() => {}
                _ => {
                    return Err(RuleValidationError::InvalidField {
                        index,
                        field: "rule_match",
                    });
                }
            }
        }
        Ok(content.trim().as_bytes().to_vec())
    }
}

/// Codec for the Vectorscan keyword bundle (`vectorscan_list`). It shares the
/// JSON `{ "rules": [...] }` envelope but its elements are keyword entries rather
/// than regex rules, so only the envelope is enforced here.
struct KeywordBundleCodec;

impl RuleCodec for KeywordBundleCodec {
    fn build_update_body(&self, content: &str) -> Result<Vec<u8>, RuleValidationError> {
        let _ = parse_rules_array(content)?;
        Ok(content.trim().as_bytes().to_vec())
    }
}

/// Codec for the line-delimited scanner allowlist (`scanners`). The on-disk file
/// is raw text, but the WAF update body is `{ "lines": [...] }`, so this collects
/// the non-empty lines and wraps them.
struct LineListCodec;

impl RuleCodec for LineListCodec {
    fn build_update_body(&self, content: &str) -> Result<Vec<u8>, RuleValidationError> {
        let lines: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if lines.is_empty() {
            return Err(RuleValidationError::Empty);
        }
        let body = json!({ "lines": lines });
        match serde_json::to_vec(&body) {
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(RuleValidationError::InvalidJson(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RULE: &str = r#"{
      "rules": [
        {
          "enable": 1,
          "http_action": "Request",
          "title": "Command injection separators body",
          "severity": "critical",
          "cwe": "CWE-78",
          "description": "Detects shell metacharacters.",
          "url": "https://cwe.mitre.org/data/definitions/78.html",
          "rule_match": "(?i)(?:;\\s*(?:wget|curl))",
          "id": "00001",
          "score": 1000
        }
      ]
    }"#;

    #[test]
    fn parse_resolves_only_the_allowlist() {
        assert_eq!(
            RegexRuleList::parse("body_regex"),
            Some(RegexRuleList::BodyRegex)
        );
        assert_eq!(
            RegexRuleList::parse("scanners"),
            Some(RegexRuleList::Scanners)
        );
        assert_eq!(RegexRuleList::parse("etc_passwd"), None);
        assert_eq!(RegexRuleList::parse("../body_regex"), None);
        assert_eq!(RegexRuleList::parse(""), None);
    }

    #[test]
    fn editor_mode_is_text_only_for_scanners() {
        assert_eq!(RegexRuleList::Scanners.editor_mode(), "ace/mode/text");
        assert_eq!(RegexRuleList::BodyRegex.editor_mode(), "ace/mode/json");
        assert_eq!(RegexRuleList::VectorscanList.editor_mode(), "ace/mode/json");
    }

    #[test]
    fn regex_bundle_accepts_a_complete_rule_and_preserves_bytes() {
        let body = codec_for(RegexRuleList::BodyRegex)
            .build_update_body(VALID_RULE)
            .expect("valid rule must pass");
        assert_eq!(body, VALID_RULE.trim().as_bytes());
    }

    #[test]
    fn regex_bundle_rejects_empty_input() {
        let error = codec_for(RegexRuleList::BodyRegex)
            .build_update_body("   \n  ")
            .expect_err("empty must fail");
        assert_eq!(error, RuleValidationError::Empty);
        assert_eq!(error.to_string(), "The rule file cannot be empty.");
    }

    #[test]
    fn regex_bundle_rejects_broken_json() {
        let error = codec_for(RegexRuleList::BodyRegex)
            .build_update_body("{ \"rules\": [ ")
            .expect_err("broken json must fail");
        assert!(matches!(error, RuleValidationError::InvalidJson(_)));
    }

    #[test]
    fn regex_bundle_rejects_missing_rules_array() {
        let error = codec_for(RegexRuleList::BodyRegex)
            .build_update_body(r#"{"data": []}"#)
            .expect_err("missing rules must fail");
        assert_eq!(error, RuleValidationError::MissingRulesArray);
    }

    #[test]
    fn regex_bundle_rejects_empty_rules_array() {
        let error = codec_for(RegexRuleList::BodyRegex)
            .build_update_body(r#"{"rules": []}"#)
            .expect_err("empty rules must fail");
        assert_eq!(error, RuleValidationError::EmptyRules);
    }

    #[test]
    fn regex_bundle_reports_the_missing_field_and_index() {
        let missing = r#"{"rules": [{"enable": 1, "http_action": "Request"}]}"#;
        let error = codec_for(RegexRuleList::BodyRegex)
            .build_update_body(missing)
            .expect_err("missing field must fail");
        assert_eq!(
            error,
            RuleValidationError::MissingField {
                index: 0,
                field: "title"
            }
        );
        assert_eq!(
            error.to_string(),
            "Rule #1 is missing the required \"title\" field."
        );
    }

    #[test]
    fn regex_bundle_rejects_empty_rule_match() {
        let blank = VALID_RULE.replace(r#""(?i)(?:;\\s*(?:wget|curl))""#, r#""""#);
        let error = codec_for(RegexRuleList::BodyRegex)
            .build_update_body(&blank)
            .expect_err("empty rule_match must fail");
        assert_eq!(
            error,
            RuleValidationError::InvalidField {
                index: 0,
                field: "rule_match"
            }
        );
    }

    #[test]
    fn keyword_bundle_only_enforces_the_envelope() {
        let keywords = r#"{"rules": [{"keyword": "evil"}, {"keyword": "bad"}]}"#;
        let body = codec_for(RegexRuleList::VectorscanList)
            .build_update_body(keywords)
            .expect("keyword bundle must pass the envelope check");
        assert_eq!(body, keywords.as_bytes());

        let error = codec_for(RegexRuleList::VectorscanList)
            .build_update_body("{}")
            .expect_err("missing rules must fail");
        assert_eq!(error, RuleValidationError::MissingRulesArray);
    }

    #[test]
    fn scanner_list_wraps_lines_and_drops_blanks() {
        let text = "arachni\n  sqlmap  \n\n\nnikto\n";
        let body = codec_for(RegexRuleList::Scanners)
            .build_update_body(text)
            .expect("scanner list must pass");
        let parsed: Value = serde_json::from_slice(&body).expect("valid json body");
        assert_eq!(parsed, json!({ "lines": ["arachni", "sqlmap", "nikto"] }));
    }

    #[test]
    fn scanner_list_rejects_blank_only_input() {
        let error = codec_for(RegexRuleList::Scanners)
            .build_update_body("   \n\n   \n")
            .expect_err("blank scanner list must fail");
        assert_eq!(error, RuleValidationError::Empty);
    }
}
