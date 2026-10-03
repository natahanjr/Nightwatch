import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from nightwatch.phishing import check_url, check_email, verify_url


def test_legit_paypal_is_safe():
    result = check_url("https://www.paypal.com/invoice")
    assert result["verdict"] == "safe"
    assert result["score"] == 0


def test_legit_google_is_safe():
    result = check_url("https://www.google.com/search?q=paypal")
    assert result["verdict"] == "safe"
    assert result["flags"] == []


def test_typosquatted_brand():
    result = check_url("https://paypai.com/account/update")
    assert result["verdict"] == "suspicious"
    assert result["score"] == 45
    assert "brand-impersonation:paypal" in result["flags"]


def test_two_edit_distance_typosquat():
    result = check_url("https://goolge.com/signin")
    assert result["score"] == 45
    assert "brand-impersonation:google" in result["flags"]


def test_suspicious_tld_with_keywords():
    result = check_url("https://secure-login-bank.tk")
    assert result["verdict"] == "phishing"
    assert result["score"] >= 70
    assert "suspicious-tld" in result["flags"]
    assert "hyphenated-domain" in result["flags"]


def test_url_shortener():
    result = check_url("https://bit.ly/3xYzAbc")
    assert result["verdict"] == "suspicious"
    assert result["shortened"] is True


def test_ip_literal_host():
    result = check_url("http://192.168.1.1/verify")
    assert result["verdict"] == "suspicious"
    assert "ip-literal-host" in result["flags"]


def test_punycode_homograph():
    result = check_url("https://xn--80ak6aa92e.com")
    assert "punycode-homograph" in result["flags"]


def test_credentials_in_url():
    result = check_url("https://paypal.com@evil.io/login")
    assert "credentials-in-url" in result["flags"]


def test_missing_host_is_flagged():
    result = check_url("ftp:///")
    assert result["verdict"] == "phishing"


def test_check_email_aggregates_verdicts():
    body = (
        "Dear customer, verify your account here: https://bit.ly/3xYzAbc\n"
        "Also check https://www.amazon.com/orders\n"
    )
    result = check_email(body)
    assert result["urls_checked"] == 2
    assert result["overall_verdict"] == "suspicious"
    assert result["results"][0]["shortened"] is True
    assert result["results"][1]["verdict"] == "safe"


def test_verify_url_non_resolving_domain():
    result = verify_url("http://nonexistent-domain-xyz-12345.invalid/")
    assert result["resolves"] is False
    assert result["error"]


def test_blocklist_match_and_flag(tmp_path):
    from nightwatch.phishing.detector import (load_blocklist, check_intel,
                                              check_url)
    bl = tmp_path / "blocklist.txt"
    bl.write_text("bad-domain.com\n# comment\n.evil.test\n", encoding="utf-8")
    indicators = load_blocklist(str(bl))
    assert "bad-domain.com" in indicators
    assert check_intel("http://sub.bad-domain.com/x", indicators) == \
        "bad-domain.com"
    assert check_intel("http://ok.test", indicators) is None
    result = check_url("http://bad-domain.com/login", blocklist=indicators)
    assert any(f.startswith("blocklist-match:") for f in result["flags"])


def test_blocklist_keyword_does_not_false_positive():
    from nightwatch.phishing.detector import check_intel
    # A bare keyword indicator must only match a host, not a path substring,
    # so a legitimate login page is not flagged.
    indicators = {"login"}
    assert check_intel("https://bank.com/login", indicators) is None
    assert check_intel("https://login.example.com/x", indicators) is None
    # A full-URL indicator still matches as a substring.
    url_indicators = {"http://evil.test/login"}
    assert check_intel("http://evil.test/login?x=1", url_indicators) == \
        "http://evil.test/login"
    # A domain indicator matches the exact or sub-domain host.
    domain_indicators = {"evil.com"}
    assert check_intel("http://sub.evil.com/x", domain_indicators) == "evil.com"


def test_extract_urls_bare_and_defanged():
    from nightwatch.phishing.detector import extract_urls
    text = (
        "Visit www.bank-secure.com now or hxxps://phish[.]example[.]com "
        "and (click.)at.attack.org"
    )
    urls = extract_urls(text)
    assert any("www.bank-secure.com" in u for u in urls)
    assert any("phish.example.com" in u for u in urls)
    # the (click.) defanged artifact should not leak a bogus host
    assert not any("click." in u for u in urls)


def test_homoglyph_brand_impersonation():
    # Cyrillic 'о' (U+043E) inside "microsoft"
    url = "https://micros" + "\u043e" + "ft.com/login"
    result = check_url(url)
    assert "unicode-homoglyph" in result["flags"]
    assert "brand-impersonation:microsoft" in result["flags"]


def test_verify_url_redirect_chain():
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/end")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = verify_url(f"http://127.0.0.1:{port}/start")
        assert result["resolves"] is True
        assert result["redirects"] == [f"http://127.0.0.1:{port}/end"]
        assert result["redirect_count"] == 1
        assert result["final_url"] == f"http://127.0.0.1:{port}/end"
        assert result["error"] is None
    finally:
        server.shutdown()
        thread.join(timeout=5)
