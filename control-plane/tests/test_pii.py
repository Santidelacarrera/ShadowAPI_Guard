from app.pii import redact_body, redact_text, rut_ok, luhn_ok


def test_card_luhn_only():
    out, c = redact_text("pay 4111 1111 1111 1111 now, order 1234 5678, ref 4111 1111 1111")
    assert out.count("[REDACTED:CARD]") == 1 and c["CARD"] == 1
    assert "order 1234 5678" in out  # too short to be a card
    assert "ref 4111 1111 1111" in out  # 12 digits: below the card length range
    # over-redaction is preferred to leaks: a card glued to other digits is still found
    assert "4111111111111111" not in redact_text("id 4111111111111111 7")[0]


def test_rut_check_digit():
    assert rut_ok("12.345.678-5") and not rut_ok("12.345.678-9")
    out, c = redact_text("rut 12.345.678-5 y 12.345.678-9")
    assert c["RUT"] == 1 and "12.345.678-9" in out


def test_email_jwt_bearer_apikey():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.abcdef"
    text = f"mail a@b.cl token {jwt} Authorization: Bearer abcdefghijkl key sk_live_abcdefgh12345678"
    out, c = redact_text(text)
    for leaked in ("a@b.cl", jwt, "abcdefghijkl", "sk_live_abcdefgh12345678"):
        assert leaked not in out
    assert c["EMAIL"] == 1 and c["JWT"] == 1 and c["APIKEY"] == 1


def test_secret_kv_and_json():
    out, c = redact_text("user=bob&password=hunter2&x=1")
    assert "hunter2" not in out and "user=bob" in out
    body, c = redact_body('{"name":"Ana","password":"p4ss","note":"mail ana@x.io","n":{"api_key":"k"}}')
    assert "p4ss" not in body and "ana@x.io" not in body and '"k"' not in body and "Ana" in body
    assert c["SECRET"] == 2 and c["EMAIL"] == 1


def test_luhn():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")


def test_masking_keeps_json_valid():
    import json
    out, _ = redact_text('{"db_password":"hunter2","n":1}')
    assert json.loads(out)["db_password"] == "[REDACTED:SECRET]"


def test_compound_secret_keys():
    body, _ = redact_body('{"db_password":"hunter2","x-api-key":"abc","user":"bob"}')
    assert "hunter2" not in body and "abc" not in body and "bob" in body


def test_phone_and_iban():
    from app.pii import iban_ok
    out, c = redact_text("call +56 9 8765 4321 or +1 (415) 555-2671; iban GB82 WEST 1234 5698 7654 32 ok; bad GB00 WEST 1234 5698 7654 32")
    assert c["PHONE"] == 2 and c["IBAN"] == 1
    assert "8765" not in out and "555-2671" not in out and "GB82" not in out and "GB00 WEST" in out
    assert iban_ok("DE89 3704 0044 0532 0130 00") and not iban_ok("DE89 3704 0044 0532 0130 01")
    assert redact_text("version 1+2 and 2024-01-02, id 123456")[0] == "version 1+2 and 2024-01-02, id 123456"
