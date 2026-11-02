import pytest

from app.utils import (
    domain_root,
    endpoint_key,
    fingerprint,
    infer_tags,
    normalize_target_url,
    parse_bulk_text,
)


@pytest.mark.parametrize("raw, expected", [
    ("app.koala.cx", "https://app.koala.cx"),
    ("  HTTPS://Mail.Koala.CX/  ", "https://mail.koala.cx"),
    ("https://langfusenew.buckleconsult.com/", "https://langfusenew.buckleconsult.com"),
    ("http://host.example.com:8080/api/", "http://host.example.com:8080/api"),
])
def test_normalize_target_url(raw, expected):
    assert normalize_target_url(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ftp://x.example.com", "https://"])
def test_normalize_rejects_invalid(raw):
    with pytest.raises(ValueError):
        normalize_target_url(raw)


def test_domain_root_groups_by_registrable_suffix():
    assert domain_root("xlsx-builder.heykoala.ai") == "heykoala.ai"
    assert domain_root("portal.dev-frontend.grubgenie.ai") == "grubgenie.ai"
    assert domain_root("localhost") == "localhost"


def test_infer_tags():
    assert infer_tags("dev-pms.koala.cx") == ["dev"]
    assert infer_tags("eb-whatsapp-middleware.koala.cx") == ["prod", "middleware"]


def test_fingerprint_is_stable_and_distinct():
    a = fingerprint("https://x.com", "cve-1", "m")
    assert a == fingerprint("https://x.com", "cve-1", "m")
    assert a != fingerprint("https://x.com", "cve-1", None)
    assert a != fingerprint("https://y.com", "cve-1", "m")


def test_parse_bulk_text_handles_csv_comments_and_headers():
    text = """url,tags
# comment line

https://a.koala.cx
https://b.koala.cx , prod;middleware
"""
    assert parse_bulk_text(text) == [
        ("https://a.koala.cx", []),
        ("https://b.koala.cx", ["prod", "middleware"]),
    ]


def test_endpoint_key_ignores_values_but_not_path_or_param_names():
    from app.utils import endpoint_key
    a = endpoint_key("http://h:9090/bm/sqli/0?q=1%27")
    assert a == endpoint_key("http://h:9090/bm/sqli/0?q=admin+or+1%3D1")  # same endpoint, other payload
    assert a != endpoint_key("http://h:9090/bm/sqli/1?q=1")  # other path
    assert a != endpoint_key("http://h:9090/bm/sqli/0?id=1")  # other parameter name
    assert endpoint_key("") == ""


def test_endpoint_makes_one_template_many_findings():
    from app.utils import endpoint_key
    base = fingerprint("http://h:9090", "reflection-ssti", "m")
    assert base == fingerprint("http://h:9090", "reflection-ssti", "m", "")  # old key unchanged
    fp1 = fingerprint("http://h:9090", "reflection-ssti", "m", endpoint_key("http://h:9090/bm/ssti/1?q=x"))
    fp2 = fingerprint("http://h:9090", "reflection-ssti", "m", endpoint_key("http://h:9090/bm/ssti/2?q=x"))
    assert fp1 != fp2 and fp1 != base
