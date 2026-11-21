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


# Real procfs collection must preserve valid Unicode, including characters
# whose UTF-8 continuation bytes overlap the terminal C1 control range.
for name in ("Û", "é", "€", "😀", "ctrl-\x1b", "del-\x7f", "c1-\u009b"):
    result = subprocess.run(
        ["./netcap_advanced_test", "--process-json", name],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (not result.stdout.isascii()
            or b"\x1b" in result.stdout or b"\x7f" in result.stdout):
        raise SystemExit("JSON contains terminal control or non-ASCII bytes")
    process = json.loads(result.stdout)
    for value in (process["comm"], process["exe"], process["unit"],
                  process["defenses"]["lsm"]):
        if value != name:
            raise SystemExit("process metadata lost Unicode fidelity")

# Literal escape-looking text must stay literal, not be interpreted as bytes.
name = r"\xC3\x9B"
result = subprocess.run(
    ["./netcap_advanced_test", "--text-json", name],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if list(process_names(json.loads(result.stdout))) != [name]:
    raise SystemExit("literal backslash sequence changed representation")
