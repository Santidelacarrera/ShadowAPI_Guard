from app.paths import matches, normalize_catalog_path, templatize


def test_templatize():
    assert templatize("/users/42/orders?x=1") == "/users/{id}/orders"
    assert templatize("/i/123e4567-e89b-12d3-a456-426614174000/") == "/i/{id}"
    assert templatize("/") == "/"


def test_match():
    c = normalize_catalog_path("/users/{userId}")
    assert c == "/users/{id}"
    assert matches(c, "/users/{id}") and matches(c, "/users/alice")
    assert not matches(c, "/users/{id}/orders") and not matches(c, "/admin/x")


def test_sanity_and_negative_ids():
    from app.paths import is_sane
    assert templatize("/a/-1") == "/a/{id}"
    assert is_sane("/users/42?x=<b>") and not is_sane("/a/' OR '1'='1") and not is_sane("/x/<script>")
