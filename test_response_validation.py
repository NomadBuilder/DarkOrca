"""Tests for HTTP response accessibility validation."""

import unittest

from src.utils.response_validation import (
    content_looks_like_error_page,
    is_accessible_response,
    is_blocked_status,
)


class MockResponse:
    def __init__(self, status_code, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class ResponseValidationTests(unittest.TestCase):
    def test_blocked_status_codes(self):
        self.assertTrue(is_blocked_status(403))
        self.assertTrue(is_blocked_status(404))
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

    def test_plain_text_file_is_accessible(self):
        response = MockResponse(200, "DB_NAME=wordpress\nDB_USER=admin", {"Content-Type": "text/plain"})
        self.assertTrue(is_accessible_response(response))

    def test_error_title_detection(self):
        body = "<html><head><title>403 Forbidden</title></head><body></body></html>"
        self.assertTrue(content_looks_like_error_page(body, content_type="text/html"))


if __name__ == "__main__":
    unittest.main()
