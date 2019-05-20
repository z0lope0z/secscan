import argparse
import requests
import sys
import json
import os

from collections import defaultdict

class SecurityScanner:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def scan(self, tags):
        reports = []
        for tag in tags:
            repo = "{}/{}".format(tag["Organisation"], tag["Repository"])
            image_tag = tag["Tag"]
            reports.append(self.__find_vulns(repo, image_tag))
        self.__dump_result(reports)

    def __dump_result(self, reports):
        print(json.dumps(reports, indent = 4, sort_keys = True))

    def __fetch_image_by_tag(self, repo, tag):
        url = "{}/repository/{}".format(self.endpoint, repo)
        response = requests.get(url).json()
        found_tag = None
        for key, response_tag in response["tags"].items():
            if key == tag:
                found_tag = response_tag
        return found_tag

    def __secscan(self, repo, image_id):
        url = "{}/repository/{}/image/{}/security?vulnerabilities=true".format(self.endpoint, repo, image_id)
        response = requests.get(url)
        return response.json()["data"]["Layer"]["Features"]

    def __find_vulns(self, repo, tag):
        found_tag = self.__fetch_image_by_tag(repo, tag)
        image_id = found_tag["image_id"]
        pkgs = self.__secscan(repo, image_id)
        sec_map = defaultdict(str)
        for pkg in pkgs:
            if "Vulnerabilities" not in pkg.keys():
                continue
            for vuln in pkg["Vulnerabilities"]:
                sec_map[vuln["Name"]] = vuln
        vulns = sec_map.values()
        org, repo = repo.split("/")
        return {
            "Organisation": org,
            "Repository": repo,
            "Tag": found_tag["name"],
            "Manifest": found_tag["manifest_digest"],
            "Vulnerabilities": vulns
        }

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
else:
    tags = json.load(sys.stdin)
    scanner.scan(tags)
