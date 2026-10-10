//! L7 path templating used to infer OpenAPI paths from observed traffic.

/// Replace dynamic segments (numeric ids, UUIDs) with `{id}` so that
/// `/users/42/orders` and `/users/43/orders` collapse into one operation.
pub fn templatize(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let segs: Vec<&str> = path
        .split('/')
        .map(|s| if is_dynamic(s) { "{id}" } else { s })
        .collect();
    segs.join("/")
}

fn is_dynamic(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.bytes().all(|b| b.is_ascii_digit())
            || (seg.len() == 36
                && seg.bytes().filter(|&b| b == b'-').count() == 4
                && seg.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_ids() {
        assert_eq!(templatize("/users/42/orders?x=1"), "/users/{id}/orders");
        assert_eq!(
            templatize("/items/123e4567-e89b-12d3-a456-426614174000"),
            "/items/{id}"
        );
        assert_eq!(templatize("/health"), "/health");
    }
}
