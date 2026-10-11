import json

from hypothesis import given, settings, strategies as st

from app.pii import luhn_ok, redact_body, redact_text, rut_ok

noise = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40)


def luhn_number(prefix: str) -> str:
    for check in range(10):
        n = prefix + str(check)
        if luhn_ok(n):
            return n


def rut_with_dv(body: int) -> str:
    s, mul = 0, 2
    for ch in reversed(str(body)):
        s += int(ch) * mul
        mul = 2 if mul == 7 else mul + 1
    r = 11 - s % 11
    dv = "0" if r == 11 else "K" if r == 10 else str(r)
    return f"{body // 1000000}.{body // 1000 % 1000:03d}.{body % 1000:03d}-{dv}"


@settings(max_examples=200, deadline=None)
@given(pre=noise, post=noise, prefix=st.integers(10**11, 10**12).map(str))
def test_cards_never_survive(pre, post, prefix):
    card = luhn_number("4" + prefix[:14])
    out, _ = redact_text(f"{pre} {card} {post}")
    assert card not in out


@settings(max_examples=200, deadline=None)
@given(pre=noise, body=st.integers(1_000_000, 99_999_999))
def test_valid_ruts_never_survive(pre, body):
    rut = rut_with_dv(body)
    assert rut_ok(rut)
    assert rut not in redact_text(f"{pre} rut: {rut} .")[0]


@settings(max_examples=200, deadline=None)
@given(user=st.from_regex(r"[a-z][a-z0-9._]{1,10}", fullmatch=True), dom=st.from_regex(r"[a-z]{2,8}\.(com|cl|io)", fullmatch=True))
def test_emails_never_survive(user, dom):
    mail = f"{user}@{dom}"
    assert mail not in redact_text(f"x {mail} y")[0]


@settings(max_examples=200, deadline=None)
@given(text=noise)
def test_idempotent(text):
    once = redact_text(text)[0]
    assert redact_text(once)[0] == once


@settings(max_examples=150, deadline=None)
@given(secret=st.from_regex(r"[A-Za-z0-9]{8,20}", fullmatch=True), other=noise)
def test_json_stays_valid_and_secrets_removed(secret, other):
    body = json.dumps({"password": secret, "api_token": secret, "note": other, "nested": {"x-api-key": secret}})
    out, _ = redact_body(body)
    parsed = json.loads(out)  # still valid JSON
    assert secret not in out and "note" in parsed


def make_iban(country: str, bban: str) -> str:
    n = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    check = 98 - int(n) % 97
    iban = f"{country}{check:02d}{bban}"
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


@settings(max_examples=150, deadline=None)
@given(country=st.sampled_from(["DE", "GB", "FR", "ES", "CL"]), bban=st.from_regex(r"[A-Z0-9]{14,24}", fullmatch=True))
def test_valid_ibans_never_survive(country, bban):
    from app.pii import iban_ok
    iban = make_iban(country, bban)
    assert iban_ok(iban)
    assert iban not in redact_text(f"pay to {iban} today")[0]


@settings(max_examples=150, deadline=None)
@given(cc=st.integers(1, 999), rest=st.from_regex(r"[0-9]{9,11}", fullmatch=True))
def test_international_phones_never_survive(cc, rest):
    phone = f"+{cc} {rest[:3]} {rest[3:6]} {rest[6:]}"
    assert phone not in redact_text(f"tel {phone}.")[0]
