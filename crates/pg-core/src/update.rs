//! Update-check helpers (feature 004). Pure and shared so the Rust/companion and Kotlin sides
//! agree on what "newer" means. Fetching is done by each app; this only parses and compares.

/// Extracts `tag_name` from the GitHub "latest release" JSON, without a JSON dependency beyond
/// serde_json (callers pass the raw body). Returns the tag as published (e.g. "v0.2.0").
pub fn parse_latest_tag(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let tag = v.get("tag_name")?.as_str()?.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

/// Parses a dotted numeric version, ignoring a leading `v` and any pre-release/build suffix.
/// Missing components are 0: `1.2` → `[1,2,0]`. Unpardsable → all zeros.
fn parts(version: &str) -> [u64; 3] {
    let v = version.trim().trim_start_matches(['v', 'V']);
    let core = v.split(['-', '+']).next().unwrap_or("");
    let mut out = [0u64; 3];
    for (i, seg) in core.split('.').take(3).enumerate() {
        // Take the leading digits of each segment, so "2rc" → 2 and "" → 0.
        let n: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
        out[i] = n.parse().unwrap_or(0);
    }
    out
}

/// True only when `latest` is strictly greater than `current`.
pub fn is_newer(current: &str, latest: &str) -> bool {
    parts(latest) > parts(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_strictly_and_tolerates_formatting() {
        assert!(is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("v0.1.0", "v0.1.1"));
        assert!(is_newer("1.0.0", "2.0.0"));
        assert!(is_newer("0.9.9", "1.0.0"));
        assert!(!is_newer("0.2.0", "0.2.0"), "equal is not newer");
        assert!(!is_newer("0.2.0", "0.1.9"), "older is not newer");
        assert!(!is_newer("1.0.0", "1.0"), "1.0 == 1.0.0");
        assert!(is_newer("1.0", "1.0.1"));
        assert!(is_newer("v0.2.0", "v0.2.1-rc1"), "numeric core wins, suffix ignored");
        assert!(!is_newer("v0.2.1", "v0.2.1-rc1"), "same core, suffix ignored");
        assert!(!is_newer("0.2.0", "garbage"), "unparsable latest is treated as 0.0.0");
    }

    #[test]
    fn reads_github_tag() {
        assert_eq!(parse_latest_tag(r#"{"tag_name":"v0.2.0","name":"PhoneGate 0.2.0"}"#).as_deref(), Some("v0.2.0"));
        assert_eq!(parse_latest_tag(r#"{"message":"Not Found"}"#), None);
        assert_eq!(parse_latest_tag("not json"), None);
        assert_eq!(parse_latest_tag(r#"{"tag_name":"  "}"#), None);
    }
}
