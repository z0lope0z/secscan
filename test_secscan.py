import unittest

from secscan import SecurityScanner, TagNotFoundException, RepositoryNotFoundException, RepositoryRestrictedException

class SecurityScannerTestCase(unittest.TestCase):
    """Tests for `nat_balancer.py`."""
    ENDPOINT = "https://quay.io/api/v1"

    def valid_image_tag(self):
        return [{
            "Organisation":"coreos",
            "Repository":"dnsmasq",
            "Tag":"v0.4.0"
        }]

    def invalid_image_tag(self):
        return [{
            "Organisation":"coreos",
            "Repository":"dnsmasq",
            "Tag":"INVALID"
        }]

    def invalid_repository(self):
        return [{
            "Organisation":"12311aaeq",
            "Repository":"aaaaa1111132",
            "Tag":"v0.4.0"
        }]

    def test_valid_image_tag(self):
        """Instances have weights across different subnets"""
        scanner = SecurityScanner(self.ENDPOINT)
        scanner.scan(self.valid_image_tag())

    def test_invalid_image_tag(self):
        """Instances have weights across different subnets"""
        scanner = SecurityScanner(self.ENDPOINT)
        with self.assertRaises(TagNotFoundException) as context:
            scanner.scan(self.invalid_image_tag())

    def test_invalid_repository(self):
        """Instances have weights across different subnets"""
        scanner = SecurityScanner(self.ENDPOINT)
        with self.assertRaises(RepositoryRestrictedException) as context:
            scanner.scan(self.invalid_repository())

if __name__ == '__main__':
    unittest.main()
