#!/usr/bin/env python3

import json
import subprocess


result = subprocess.run(
    ["./netcap_advanced_test", "--invalid-utf8-json"],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
report = json.loads(result.stdout)


def process_names(value):
    if isinstance(value, dict):
        if "comm" in value:
            yield value["comm"]
        for child in value.values():
            yield from process_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from process_names(child)


if list(process_names(report)) != ["invalid-\u00ff"]:
    raise SystemExit("invalid process-name byte changed representation")
