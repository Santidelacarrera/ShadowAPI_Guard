"""Path templating and matching between observed traffic and OpenAPI templates."""
import re

_NUM = re.compile(r"^-?\d+$")
_SANE = re.compile(r"^[A-Za-z0-9._~\-{}/%:@!$&()*+,=]*$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_OID = re.compile(r"^[0-9a-fA-F]{24}$")
_PARAM = re.compile(r"^\{[^{}]+\}$")


def split_query(path: str) -> tuple[str, str]:
    p, _, q = path.partition("?")
    return p, q


def templatize(path: str) -> str:
    """/users/42/orders?x=1 -> /users/{id}/orders (keep in sync with reconstructor/src/lib.rs)."""
    path = split_query(path)[0] or "/"
    segs = ["{id}" if (_NUM.match(s) or _UUID.match(s) or _OID.match(s)) else s for s in path.split("/")]
    out = "/".join(segs)
    if len(out) > 1:
        out = out.rstrip("/")
    return out or "/"


def normalize_catalog_path(path: str) -> str:
    """Canonicalise an OpenAPI path: every {param} becomes {id}."""
    segs = ["{id}" if _PARAM.match(s) else s for s in path.split("/")]
    out = "/".join(segs)
    return out.rstrip("/") if len(out) > 1 else out or "/"


def matches(catalog_path: str, observed_path: str) -> bool:
    """An observed template matches a catalog path when literals are equal and catalog params match any segment."""
    c, o = catalog_path.split("/"), observed_path.split("/")
    if len(c) != len(o):
        return False
    return all(cs == os_ or cs == "{id}" for cs, os_ in zip(c, o))


def is_sane(path: str) -> bool:
    """False for paths carrying quotes, spaces, angle brackets...: scanner/attack noise, not real endpoints."""
    return bool(_SANE.match(split_query(path)[0]))
