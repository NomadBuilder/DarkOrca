"""Tests for site platform selection and scanner gating."""

import unittest

from src.models.platform import SitePlatform, should_enable_scanner, WORDPRESS_SCANNERS
from src.utils.scan_presets import get_allowed_scanners_for_preset, resolve_scan_config


class PlatformSelectionTests(unittest.TestCase):
    def test_platform_aliases(self):
        self.assertEqual(SitePlatform.from_value("wp"), SitePlatform.WORDPRESS)
        self.assertEqual(SitePlatform.from_value("sqsp"), SitePlatform.SQUARESPACE)
        self.assertEqual(SitePlatform.from_value("unknown"), SitePlatform.OTHER)

    def test_wordpress_scanners_only_on_wordpress(self):
        for name in WORDPRESS_SCANNERS:
            self.assertTrue(should_enable_scanner(name, SitePlatform.WORDPRESS))
            self.assertFalse(should_enable_scanner(name, SitePlatform.SQUARESPACE))
            self.assertFalse(should_enable_scanner(name, SitePlatform.OTHER))

    def test_squarespace_scanner_gating(self):
        self.assertTrue(should_enable_scanner("squarespace_analyzer", SitePlatform.SQUARESPACE))
        self.assertFalse(should_enable_scanner("squarespace_analyzer", SitePlatform.WORDPRESS))
        self.assertTrue(should_enable_scanner("ssl_analyzer", SitePlatform.SQUARESPACE))

    def test_resolve_disables_wpscan_for_non_wp(self):
        config = resolve_scan_config({"scan_preset": "standard", "platform": "squarespace"})
        self.assertEqual(config["platform"], "squarespace")
        self.assertFalse(config["enable_wpscan"])

        wp_config = resolve_scan_config({"scan_preset": "standard", "platform": "wordpress"})
        self.assertTrue(wp_config["enable_wpscan"])

    def test_quick_allowlist_excludes_wp_for_squarespace(self):
        allowed = get_allowed_scanners_for_preset("quick", SitePlatform.SQUARESPACE)
        self.assertIsNotNone(allowed)
        self.assertIn("squarespace_analyzer", allowed)
        self.assertNotIn("wordpress_analyzer", allowed)
        self.assertNotIn("wpscan", allowed)


if __name__ == "__main__":
    unittest.main()
