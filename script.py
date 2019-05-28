import argparse
import json
import os
import sys

from secscan import SecurityScanner

endpoint = os.getenv("QUAY_API_ENDPOINT", "https://quay.io/api/v1")

parser = argparse.ArgumentParser(
    description = "Find vulnerabilities for a given file or read from stdin. File must be in the correct format"
)
parser.add_argument("--file", help = "file containing the image tag to look up")
parser.add_argument("data", nargs="?", help = "json stream of lookup tags from stdin")

scanner = SecurityScanner(endpoint)

lookup_file = parser.parse_args().file
if lookup_file:
    with open(lookup_file, "r") as lookup_file:
        data = lookup_file.read()
        tags = json.loads(data)
        scanner.scan(tags)
elif sys.stdin:
    tags = json.load(sys.stdin)
    scanner.scan(tags)
