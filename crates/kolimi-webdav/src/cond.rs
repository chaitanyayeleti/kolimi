use std::time::{Duration, UNIX_EPOCH};

/// Formats a Unix-millisecond timestamp as an HTTP date (RFC 7231).
pub fn http_date(ms: i64) -> String {
    let millis = ms.max(0) as u64;
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_millis(millis))
}

/// Formats a Unix-millisecond timestamp as RFC 3339 (used by `creationdate`).
pub fn rfc3339(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Returns whether an `If-None-Match`/`If-Match` header value matches `etag`.
///
/// `allow_weak` controls whether `W/"..."` candidates compare equal
/// (allowed for `If-None-Match`, forbidden for `If-Match`).
pub fn matches_etag(header: &str, etag: &str, allow_weak: bool) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        if candidate == "*" {
            return true;
        }
        if candidate == etag {
            return true;
        }
        allow_weak && candidate.strip_prefix("W/") == Some(etag)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_formats_epoch() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn rfc3339_formats_epoch() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn etag_matching_rules() {
        assert!(matches_etag("*", "\"abc\"", false));
        assert!(matches_etag("\"abc\"", "\"abc\"", false));
        assert!(!matches_etag("\"xyz\"", "\"abc\"", false));
        assert!(matches_etag("W/\"abc\"", "\"abc\"", true));
        assert!(!matches_etag("W/\"abc\"", "\"abc\"", false));
        assert!(matches_etag("\"a\", \"abc\"", "\"abc\"", false));
    }
}
