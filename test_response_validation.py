"""Tests for HTTP response accessibility validation."""

import unittest

from src.utils.response_validation import (
    clear_baseline_cache,
    content_looks_like_error_page,
    is_accessible_response,
    is_blocked_status,
    is_plausible_resource_response,
    matches_soft_404_baseline,
)


class MockResponse:
    def __init__(self, status_code, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class ResponseValidationTests(unittest.TestCase):
    def setUp(self):
        clear_baseline_cache()

    def test_blocked_status_codes(self):
        self.assertTrue(is_blocked_status(403))
        self.assertTrue(is_blocked_status(404))
        self.assertTrue(is_blocked_status(429))
        self.assertFalse(is_blocked_status(200))

    def test_nginx_403_page_not_accessible(self):
        body = """<html>
        <head><title>403 Forbidden</title></head>
        <body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body>
        </html>"""
        response = MockResponse(200, body, {"Content-Type": "text/html"})
        self.assertFalse(is_accessible_response(response))

    def test_nginx_404_page_not_accessible(self):
        body = """<html><head><title>404 Not Found</title></head>
        <body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>"""
        response = MockResponse(200, body, {"Content-Type": "text/html"})
        self.assertFalse(is_accessible_response(response))

    def test_real_403_status_not_accessible(self):
        response = MockResponse(403, "Forbidden")
        self.assertFalse(is_accessible_response(response))

    def test_429_status_not_accessible(self):
        response = MockResponse(429, "Too Many Requests")
        self.assertFalse(is_accessible_response(response))

    def test_plain_text_file_is_accessible(self):
        response = MockResponse(200, "DB_NAME=wordpress\nDB_USER=admin", {"Content-Type": "text/plain"})
        self.assertTrue(
            is_accessible_response(response, resource_path="/wp-config.php")
        )

    def test_htaccess_html_404_not_plausible(self):
        body = """<!DOCTYPE html><html><head><title>My Site</title></head>
        <body><h1>Oops! That page can't be found.</h1></body></html>"""
        response = MockResponse(200, body, {"Content-Type": "text/html"})
        self.assertFalse(is_plausible_resource_response(response, "/.htaccess"))
        self.assertFalse(
            is_accessible_response(response, resource_path="/.htaccess")
        )

    def test_real_htaccess_is_plausible(self):
        body = "RewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n"
        response = MockResponse(200, body, {"Content-Type": "text/plain"})
        self.assertTrue(is_plausible_resource_response(response, "/.htaccess"))
        self.assertTrue(
            is_accessible_response(response, resource_path="/.htaccess")
        )

    def test_soft_404_baseline_match(self):
        baseline = """<!DOCTYPE html><html><head><title>Store</title></head>
        <body><main><h1>Nothing here</h1><p>Try searching.</p></main></body></html>"""
        probe = """<!DOCTYPE html><html><head><title>Store</title></head>
        <body><main><h1>Nothing here</h1><p>Try searching.</p></main></body></html>"""
        self.assertTrue(matches_soft_404_baseline(probe, baseline))

        response = MockResponse(200, probe, {"Content-Type": "text/html"})
        self.assertFalse(
            is_accessible_response(
                response,
                resource_path="/.htaccess",
                baseline_content=baseline,
            )
        )

    def test_wordpress_themed_404_for_htaccess(self):
        baseline = """<!DOCTYPE html><html><head><title>Example WP</title></head>
        <body class="error404"><h1>It looks like nothing was found at this location.</h1></body></html>"""
        htaccess_page = baseline  # Same themed template for every missing URL
        response = MockResponse(200, htaccess_page, {"Content-Type": "text/html"})
        self.assertFalse(
            is_accessible_response(
                response,
                resource_path="/.htaccess",
                baseline_content=baseline,
            )
        )

    def test_error_title_detection(self):
        body = "<html><head><title>403 Forbidden</title></head><body></body></html>"
        self.assertTrue(content_looks_like_error_page(body, content_type="text/html"))


if __name__ == "__main__":
    unittest.main()
