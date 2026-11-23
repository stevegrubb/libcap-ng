#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the integration oracle itself before trusting privileged results."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from run import compare_cli, compare_events, copy_program


def record(tag, masks, tid=10, pid=10):
    return "{} {} {} {:016x} {:016x} {:016x}\n".format(tag, tid, pid, *masks)


class StagingTest(unittest.TestCase):
    def test_private_binary(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            source = root / "helper"
            source.write_bytes(b"\x7fELFfixture")
            source.chmod(0o4750)
            staged = root / "staged"
            staged.mkdir()
            copy_program(source, staged)
            target = staged / source.name
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(target.stat().st_uid, os.geteuid())

    def test_libtool_launcher(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / ".libs").mkdir()
            (root / "staged").mkdir()
            (root / "helper").write_text("#!/bin/sh\n# libtool launcher\n")
            (root / ".libs/helper").write_bytes(b"\x7fELFactual helper")
            copy_program(root / "helper", root / "staged")
            self.assertEqual((root / "staged/helper").read_bytes(),
                             b"\x7fELFactual helper")


class EventCheckerTest(unittest.TestCase):
    def test_single_caller(self):
        high = (1, 0x100000003, 0x100000002)
        low = (1, 3, 2)
        expected = record("EXP", high) + record("EXP", low)
        observed = record("OBS", high, tid=0) + record("OBS", low, tid=0)
        self.assertIsNone(compare_events(expected + observed, "v1"))
        damaged = {
            "missing": record("OBS", high, tid=0),
            "duplicate": observed + record("OBS", low, tid=0),
            "pid": observed.replace("OBS 0 10", "OBS 0 11"),
            "word order": record("OBS", (1, 0x300000001, 0x200000001),
                                 tid=0) + record("OBS", low, tid=0),
            "set order": record("OBS", (high[1], high[0], high[2]),
                                tid=0) + record("OBS", low, tid=0),
            "call order": record("OBS", low, tid=0) + record("OBS", high, tid=0),
            "stale": record("OBS", high, tid=0) * 2,
        }
        for name, text in damaged.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                compare_events(expected + text, "v1")
        with self.assertRaises(AssertionError):
            compare_events(expected.replace("EXP 10", "EXP 0") + observed, "v1")

    def test_concurrent_callers(self):
        a, b = (1, 1, 0), (0, 2, 2)
        expected = record("EXP", a, tid=11) * 32 + record("EXP", b, tid=12) * 32
        # Scheduling can interleave the two callers in any order. There is
        # no event TID to reconstruct it, but triples/counts must stay exact.
        observed = (record("OBS", b, tid=0) + record("OBS", a, tid=0)) * 32
        self.assertIsNone(compare_events(expected + observed, "threads"))
        damaged = observed.replace(record("OBS", a, tid=0),
                                   record("OBS", (1, 2, 0), tid=0), 1)
        with self.assertRaises(AssertionError):
            compare_events(expected + damaged, "threads")
        with self.assertRaises(AssertionError):
            compare_events(expected.replace("EXP 12", "EXP 11") + observed,
                           "threads")

    def test_empty_and_malformed(self):
        self.assertIsNone(compare_events("", "failures"))
        for text in (record("OBS", (0, 0, 0), tid=0), "OBS 0 10 0 0\n"):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                compare_events(text, "failures")
        with self.assertRaises(AssertionError):
            compare_events("", "zero")

    def test_race_coverage(self):
        text = (record("EXP", (0, 1, 0)) + record("OBS", (0, 1, 0), tid=0)) * 512
        self.assertIsNotNone(compare_events(text, "race"))
        text = text.replace(record("EXP", (0, 1, 0)), record("EXP", (1, 1, 0)), 1)
        text = text.replace(record("OBS", (0, 1, 0), tid=0),
                            record("OBS", (1, 1, 0), tid=0), 1)
        self.assertIsNone(compare_events(text, "race"))

    def test_cli(self):
        text = (record("EXP", (0, 0, 0)) +
                "[CAPSET] pid=10 effective=0x0 permitted=0x0 inheritable=0x0\n" +
                "Application exited with status 0\n" +
                json.dumps({"successful_capset_calls": 1,
                            "capability_drop_observed": True}, indent=2))
        self.assertIsNone(compare_cli(text, "zero"))
        for old, new in (("pid=10", "pid=11"), ("effective=0x0", "effective=0x1"),
                         ('"successful_capset_calls": 1',
                          '"successful_capset_calls": 2'),
                         ('"capability_drop_observed": true',
                          '"capability_drop_observed": false'),
                         ("status 0", "status 1")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                compare_cli(text.replace(old, new), "zero")
        self.assertIsNotNone(compare_cli("Application exited with status 77", "mixed"))


if __name__ == "__main__":
    unittest.main()
