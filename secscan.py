import argparse
import requests
import sys
import json
import os

from collections import defaultdict

class TagNotFoundException(Exception):
    def __init__(self, repository, tag):
        self.message = "This tag {} does not exist for repository {}".format(tag, repository)

class RepositoryNotFoundException(Exception):
    def __init__(self, repository):
        self.message = "This repository does not exist {}".format(repository)

class RepositoryRestrictedException(Exception):
    def __init__(self, repository):
        self.message = "This repository does not exist {}".format(repository)

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
        response = requests.get(url)
        status_code = response.status_code
        if status_code == 404:
            raise RepositoryNotFoundException(repo)
        if status_code == 401:
            raise RepositoryRestrictedException(repo)
        found_tag = None
        for key, response_tag in response.json()["tags"].items():
            if key == tag:
                found_tag = response_tag
        if found_tag is None:
            raise TagNotFoundException(repo, tag)
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
                vuln["PackageName"] = pkg["Name"]
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
