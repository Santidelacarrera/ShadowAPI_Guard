//! L7 reconstruction: HTTP/1.x request parsing from raw socket bytes, path templating
//! (keep in sync with control-plane/app/paths.py) and detector event serialisation.

use serde::Serialize;

/// Replace dynamic segments (numeric ids, UUIDs, 24-hex object ids) with `{id}` so that
/// `/users/42/orders` and `/users/43/orders` collapse into one operation.
pub fn templatize(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let out: Vec<&str> = path
        .split('/')
        .map(|s| if is_dynamic(s) { "{id}" } else { s })
        .collect();
    let out = out.join("/");
    if out.len() > 1 {
        out.trim_end_matches('/').to_string()
    } else if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

fn is_dynamic(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let b = seg.as_bytes();
    let digits = b.strip_prefix(b"-").filter(|d| !d.is_empty()).unwrap_or(b);
    digits.iter().all(u8::is_ascii_digit)
        || (b.len() == 24 && b.iter().all(u8::is_ascii_hexdigit))
        || (b.len() == 36
            && b.iter().filter(|&&c| c == b'-').count() == 4
            && b.iter().all(|&c| c == b'-' || c.is_ascii_hexdigit()))
}

/// Event sent to the detector (`POST /events`). Field names match the detector's `InEvent`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Event {
    pub ts: f64,
    pub method: String,
    pub path: String,
    pub host: String,
    pub status: u16,
    pub req_body: String,
    pub authorization: String,
    pub source: String,
}

const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Parse the head of an HTTP/1.x request captured from a socket write. Returns `None` for
/// anything that is not a well-formed request line (responses, TLS records, binary data).
/// Truncated captures are fine: headers/body that were cut off are simply missing.
pub fn parse_request(buf: &[u8]) -> Option<Event> {
    let text = String::from_utf8_lossy(buf);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => (text.as_ref(), ""),
    };
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if !METHODS.contains(&method) || !version.starts_with("HTTP/1.") || !path.starts_with('/') {
        return None;
    }
    let (mut host, mut authorization) = (String::new(), String::new());
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "host" => host = v.trim().to_string(),
                "authorization" => authorization = v.trim().to_string(),
                _ => {}
            }
        }
    }
    Some(Event {
        ts: 0.0,
        method: method.to_string(),
        path: path.to_string(),
        host,
        status: 0,
        req_body: body.trim_end_matches('\0').to_string(),
        authorization,
        source: "ebpf".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_ids() {
        assert_eq!(templatize("/users/42/orders?x=1"), "/users/{id}/orders");
        assert_eq!(templatize("/items/123e4567-e89b-12d3-a456-426614174000/"), "/items/{id}");
        assert_eq!(templatize("/o/507f1f77bcf86cd799439011"), "/o/{id}");
        assert_eq!(templatize("/a/-1"), "/a/{id}");
        assert_eq!(templatize("/health"), "/health");
        assert_eq!(templatize("/"), "/");
    }

    #[test]
    fn parses_request() {
        let raw = b"POST /users/7/orders?x=1 HTTP/1.1\r\nHost: api.local\r\nAuthorization: Bearer abc\r\n\r\n{\"a\":1}\0\0";
        let e = parse_request(raw).unwrap();
        assert_eq!((e.method.as_str(), e.path.as_str()), ("POST", "/users/7/orders?x=1"));
        assert_eq!((e.host.as_str(), e.authorization.as_str()), ("api.local", "Bearer abc"));
        assert_eq!(e.req_body, "{\"a\":1}");
    }

    #[test]
    fn parses_truncated_and_rejects_non_http() {
        assert!(parse_request(b"GET /a HTTP/1.1\r\nHost: x").is_some());
        assert!(parse_request(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
        assert!(parse_request(b"\x16\x03\x01\x02\x00").is_none());
        assert!(parse_request(b"GET nopath HTTP/1.1\r\n\r\n").is_none());
    }
}
