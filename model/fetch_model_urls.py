#!/usr/bin/env python3

# Simple Python script to fetch the built LLM files
# TODO: fetch latest release, add constants for paths in case they change, etc

import urllib.request
import json

contents = urllib.request.urlopen("https://api.github.com/repos/VibeFuzzing/llm-mutator/releases").read()
for url in map(lambda x : x["browser_download_url"], iter(json.loads(contents)[0]["assets"])):
    print(url)
