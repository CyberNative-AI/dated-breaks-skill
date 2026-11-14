"""Run: python3 -m unittest discover -s tests -v   (no network: the data is a pinned copy of six real calendar rows).

The Bounds, SymlinkRoot, SymlinkRaces and SelfScan classes are the regressions for the Security review of the first candidate."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))
import dated_breaks as db  # noqa: E402

DATA = os.path.join(HERE, "data")
DIRTY = os.path.join(HERE, "fixtures", "dirty")
CLEAN = os.path.join(HERE, "fixtures", "clean")
TODAY = "2026-11-14"


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = db.main(["--offline", DATA, "--today", TODAY, *args])
    return rc, out.getvalue(), err.getvalue()


class Fixture(unittest.TestCase):
    def test_dirty_tree_flags_gpt_4o_and_node_22(self):
        rc, out, _ = run(DIRTY, "--json")
        self.assertEqual(rc, 1)
        rows = {r["id"]: r for r in json.loads(out)["findings"]}
        gpt = rows["2027-01-14-openai-removes-gpt-4o-gpt-4-1"]
        self.assertEqual((gpt["date"], gpt["result"], gpt["daysLeft"]), ("2027-01-14", "match", 61))
        self.assertEqual((gpt["hits"][0]["path"], gpt["hits"][0]["line"]), ("src/app.py", 4))
        self.assertIn("gpt-6-luna", gpt["replacement"])
        node = rows["2027-04-30-node-22-end-of-life"]
        self.assertEqual((node["date"], node["hits"][0]["path"]), ("2027-04-30", "Dockerfile"))
        self.assertIn("Node 24", node["replacement"])
        self.assertEqual(rows["2026-11-19-postgres-latest-becomes-19"]["result"], "match")

    def test_clean_tree_flags_nothing(self):
        rc, out, _ = run(CLEAN)
        self.assertEqual(rc, 0)
        self.assertIn("No dated breaks found", out)
        self.assertEqual(json.loads(run(CLEAN, "--json")[1])["findings"], [])

    def test_text_output_names_date_and_replacement(self):
        _, out, _ = run(DIRTY)
        self.assertIn("2027-01-14  (in 61 days)  HITS", out)
        self.assertIn("found:    src/app.py:4", out)
        self.assertIn("replace:  The recommended replacement is gpt-6-luna.", out)


class Deps(unittest.TestCase):
    def test_model_before_writing_it(self):
        rc, out, _ = run("--dep", "model:gpt-5-mini")
        self.assertEqual(rc, 1)
        self.assertIn("2026-12-11", out)

    def test_new_model_is_clean(self):
        self.assertEqual(run("--dep", "model:gpt-6-luna", "--dep", "docker:node:24-slim", "--dep", "docker:postgres:18")[0], 0)

    def test_postgres_digest_and_tag_rules(self):
        self.assertEqual(run("--dep", "docker:postgres:latest")[0], 1)
        self.assertEqual(run("--dep", "docker:postgres")[0], 1)
        self.assertEqual(run("--dep", "docker:postgres:18-alpine")[0], 0)

    def test_within_hides_far_dates(self):
        self.assertEqual(run("--dep", "model:gpt-4o", "--within", "30")[0], 0)
        self.assertEqual(run("--dep", "model:gpt-4o", "--within", "90")[0], 1)

    def test_bad_dep_is_exit_2(self):
        rc, _, err = run("--dep", "nonsense")
        self.assertEqual(rc, 2)
        self.assertIn("--dep wants", err)


class Safety(unittest.TestCase):
    def test_missing_folder_and_data(self):
        self.assertEqual(run("/no/such/folder")[0], 2)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(db.main(["--offline", "/no/such/dir", CLEAN]), 2)

    def test_redirect_and_http_refused(self):
        self.assertIsNone(db._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com/"))
        with self.assertRaises(RuntimeError):
            db.fetch_json("http://cybernative.ai/breakage-calendar/entries.json")

    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            with open(os.path.join(outside, "app.py"), "w") as f:
                f.write('model = "gpt-4o"\n')
            os.symlink(outside, os.path.join(d, "link"))
            os.symlink(os.path.join(outside, "app.py"), os.path.join(d, "app.py"))
            self.assertEqual(run(d)[0], 0)


SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "dated_breaks.py")


def cli(script, *args):
    """Run the script as a user would, in its own process. Returns (exit status, stdout, stderr, seconds)."""
    t = time.time()
    r = subprocess.run([sys.executable, "-I", script, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return r.returncode, r.stdout.decode(), r.stderr.decode(), time.time() - t


def offline_with(tmp, extra_sigs=None, entries_text=None):
    """A copy of the pinned data, optionally with extra signatures (each is a dict) or a replaced entries.json."""
    d = os.path.join(tmp, "data")
    shutil.copytree(DATA, d)
    if extra_sigs:
        with open(os.path.join(d, "signatures.json")) as f:
            sigs = json.load(f)
        sigs["signatures"] += extra_sigs
        with open(os.path.join(d, "signatures.json"), "w") as f:
            json.dump(sigs, f)
    if entries_text is not None:
        with open(os.path.join(d, "entries.json"), "w") as f:
            f.write(entries_text)
    return d


def sig(patterns, files="any", needs=None):
    s = {"row": "2027-01-14-openai-removes-gpt-4o-gpt-4-1", "kind": "match", "files": files, "patterns": patterns}
    if needs:
        s["needs"] = needs
    return s


class Bounds(unittest.TestCase):
    """The downloaded regexes and the files they run over must not be able to hold the process."""

    def test_catastrophic_downloaded_pattern_is_killed_at_the_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = offline_with(tmp, [sig(["(a+)+$"])])
            proj = os.path.join(tmp, "proj")
            os.mkdir(proj)
            with open(os.path.join(proj, "x.txt"), "w") as f:
                f.write("a" * 60 + "!\n")
            rc, out, err, secs = cli(SCRIPT, "--offline", d, "--time-budget", "2", proj)
        self.assertEqual(rc, 2, (out, err))
        self.assertIn("time budget", err)
        self.assertEqual(out, "")
        self.assertLess(secs, 15)

    def test_the_control_pattern_is_really_catastrophic(self):
        # In-process Python cannot interrupt this regex, which is why the script kills a child process instead.
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([sys.executable, "-I", "-c", "import re; re.search('(a+)+$', 'a' * 30 + '!')"], timeout=2)

    def test_adverse_input_to_the_live_node_22_pattern_is_bounded(self):
        # The live row's pattern node-version:(?:.*[^.0-9])?22 is quadratic over a line of repeated prefixes.
        with tempfile.TemporaryDirectory() as tmp:
            proj = os.path.join(tmp, "proj")
            os.mkdir(proj)
            with open(os.path.join(proj, "ci.yml"), "w") as f:
                f.write("node-version:" * 80000 + "\n")  # one line, about 1 MB, under the file cap
            rc, out, err, secs = cli(SCRIPT, "--offline", DATA, "--today", TODAY, proj)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("matched on their first 4000", out)
        self.assertLess(secs, 20)

    def test_line_cap_still_finds_a_real_hit_in_the_first_4000_characters(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = os.path.join(tmp, "proj")
            os.mkdir(proj)
            with open(os.path.join(proj, "app.py"), "w") as f:
                f.write('model="gpt-4o",' + "x" * 6000 + "\n")
            rc, out, _, _ = cli(SCRIPT, "--offline", DATA, "--today", TODAY, proj)
        self.assertEqual(rc, 1)
        self.assertIn("2027-01-14", out)

    def test_bad_downloaded_data_is_exit_2_not_a_crash(self):
        cases = {
            "invalid regex": [sig(["("])],
            "pattern over the length cap": [sig(["a" * 5000])],
            "too many patterns": [sig(["a"] * 51)],
            "patterns not a list": [dict(sig(["a"]), patterns="a")],
            "file selector not text": [dict(sig(["a"]), files=7)],
            "invalid selector regex": [sig(["a"], files="(")],
            "invalid needs regex": [sig(["a"], needs="(")],
        }
        for name, extra in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                d = offline_with(tmp, extra)
                rc, out, err, _ = cli(SCRIPT, "--offline", d, CLEAN)
                self.assertEqual(rc, 2, (out, err))
                self.assertIn("refusing the downloaded search data", err)
                self.assertNotIn("Traceback", err)

    def test_malformed_entries_is_exit_2_not_a_traceback_with_status_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = offline_with(tmp, entries_text=json.dumps({"entries": [{"id": "2027-01-14-openai-removes-gpt-4o-gpt-4-1"}]}))
            rc, out, err, _ = cli(SCRIPT, "--offline", d, DIRTY)
        self.assertEqual(rc, 2, (out, err))
        self.assertNotIn("Traceback", err)

    def test_time_budget_range(self):
        for bad in ("0", "601"):
            self.assertEqual(cli(SCRIPT, "--offline", DATA, "--time-budget", bad, CLEAN)[0], 2)


@unittest.skipUnless(db.folder_scan_supported(), "folder scans need descriptor-relative non-following opens")
class SymlinkRoot(unittest.TestCase):
    """A symlinked scan folder is refused, in every spelling."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.real = os.path.join(self.tmp.name, "real")
        os.mkdir(self.real)
        with open(os.path.join(self.real, "app.py"), "w") as f:
            f.write('model = "gpt-4o"\n')
        self.link = os.path.join(self.tmp.name, "link")
        os.symlink(self.real, self.link)

    def tearDown(self):
        self.tmp.cleanup()

    def test_symlink_root_refused_in_each_spelling(self):
        for spelling in (self.link, self.link + "/", self.link + "//", self.link + "/."):
            with self.subTest(spelling):
                rc, out, err, _ = cli(SCRIPT, "--offline", DATA, spelling)
                self.assertEqual(rc, 2, (out, err))
                self.assertEqual(out, "")
                self.assertTrue("symlink" in err or "end the scan folder" in err, err)

    def test_control_the_real_folder_is_scanned(self):
        rc, out, _, _ = cli(SCRIPT, "--offline", DATA, self.real)
        self.assertEqual(rc, 1)
        self.assertIn("app.py:1", out)

    def test_relative_symlink_root_refused(self):
        r = subprocess.run([sys.executable, "-I", SCRIPT, "--offline", DATA, "link"], cwd=self.tmp.name, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 2)

    def test_walk_itself_refuses_a_symlink_root(self):
        with self.assertRaises(ValueError):
            list(db.walk(self.link, {"files": 0, "large": 0, "stopped": False, "deep": 0, "self": 0}))


@unittest.skipUnless(db.folder_scan_supported(), "folder scans need descriptor-relative non-following opens")
class SymlinkRaces(unittest.TestCase):
    """A name that is swapped between the listing and the open is not read."""

    STATS = staticmethod(lambda: {"files": 0, "large": 0, "stopped": False, "deep": 0, "self": 0})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "root")
        self.outside = os.path.join(self.tmp.name, "outside")
        os.mkdir(self.root)
        os.mkdir(self.outside)
        with open(os.path.join(self.outside, "secret.py"), "w") as f:
            f.write('SECRET = "outside-the-scan"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def swapping_stat(self, name, swap):
        orig = os.stat

        def fake(path, *a, **k):
            r = orig(path, *a, **k)
            if path == name:
                swap()
            return r
        return mock.patch.object(db.os, "stat", fake)

    def test_file_swapped_for_a_symlink_after_the_listing_is_not_read(self):
        target = os.path.join(self.root, "x.py")
        with open(target, "w") as f:
            f.write("clean = 1\n")
        with open(os.path.join(self.root, "keep.py"), "w") as f:
            f.write("keep = 1\n")

        def swap():
            os.unlink(target)
            os.symlink(os.path.join(self.outside, "secret.py"), target)
        with self.swapping_stat("x.py", swap):
            got = dict(db.walk(self.root, self.STATS()))
        self.assertEqual(sorted(got), ["keep.py"])
        self.assertFalse(any("outside-the-scan" in t for t in got.values()))

    def test_folder_swapped_for_a_symlink_after_the_listing_is_not_entered(self):
        sub = os.path.join(self.root, "sub")
        os.mkdir(sub)
        with open(os.path.join(sub, "a.py"), "w") as f:
            f.write("a = 1\n")

        def swap():
            shutil.rmtree(sub)
            os.symlink(self.outside, sub)
        with self.swapping_stat("sub", swap):
            got = dict(db.walk(self.root, self.STATS()))
        self.assertEqual(got, {})

    def test_file_swapped_for_a_pipe_is_not_opened_for_reading_or_blocked_on(self):
        target = os.path.join(self.root, "p.py")
        with open(target, "w") as f:
            f.write("p = 1\n")

        def swap():
            os.unlink(target)
            os.mkfifo(target)
        with self.swapping_stat("p.py", swap):
            got = dict(db.walk(self.root, self.STATS()))
        self.assertEqual(got, {})

    def test_pipes_and_sockets_already_in_the_tree_are_skipped(self):
        os.mkfifo(os.path.join(self.root, "fifo.py"))
        with open(os.path.join(self.root, "ok.py"), "w") as f:
            f.write("ok = 1\n")
        self.assertEqual(sorted(dict(db.walk(self.root, self.STATS()))), ["ok.py"])

    def test_symlinked_children_still_not_followed(self):
        os.symlink(self.outside, os.path.join(self.root, "dirlink"))
        os.symlink(os.path.join(self.outside, "secret.py"), os.path.join(self.root, "filelink.py"))
        self.assertEqual(dict(db.walk(self.root, self.STATS())), {})


@unittest.skipUnless(db.folder_scan_supported(), "folder scans need descriptor-relative non-following opens")
class SelfScan(unittest.TestCase):
    """A skill installed inside the project it checks must not report its own test fixtures."""

    def install(self, tmp, where):
        proj = os.path.join(tmp, "proj")
        dest = os.path.join(proj, where)
        os.makedirs(os.path.dirname(dest))
        shutil.copytree(os.path.dirname(HERE), dest, ignore=shutil.ignore_patterns("__pycache__", ".git"))
        os.makedirs(os.path.join(proj, "src"))
        return proj, os.path.join(dest, "scripts", "dated_breaks.py"), os.path.join(dest, "tests", "data")

    def test_project_level_install_reports_nothing_from_its_own_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj, script, data = self.install(tmp, os.path.join(".claude", "skills", "dated-breaks"))
            with open(os.path.join(proj, "src", "app.py"), "w") as f:
                f.write('model = "gpt-6-luna"\n')
            rc, out, err, _ = cli(script, "--offline", data, "--today", TODAY, proj)
        self.assertEqual(rc, 0, (out, err))
        self.assertNotIn("postgres", out)
        self.assertNotIn("node:22", out)
        self.assertIn("this skill's own folder was not scanned", out)

    def test_control_a_real_hit_in_the_project_is_still_found_beside_the_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj, script, data = self.install(tmp, os.path.join(".claude", "skills", "dated-breaks"))
            with open(os.path.join(proj, "src", "app.py"), "w") as f:
                f.write('model = "gpt-4o"\n')
            rc, out, _, _ = cli(script, "--offline", data, "--today", TODAY, proj)
        self.assertEqual(rc, 1)
        self.assertIn("src/app.py:1", out)
        self.assertNotIn("fixtures", out)

    def test_skill_reached_through_a_symlinked_install_is_still_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj, script, data = self.install(tmp, os.path.join("vendor-copy", "dated-breaks"))
            real = os.path.dirname(os.path.dirname(script))
            os.makedirs(os.path.join(proj, ".claude", "skills"))
            os.rename(real, os.path.join(tmp, "elsewhere"))
            os.symlink(os.path.join(tmp, "elsewhere"), os.path.join(proj, ".claude", "skills", "dated-breaks"))
            os.symlink(os.path.join(tmp, "elsewhere"), real)
            rc, out, _, _ = cli(os.path.join(proj, ".claude", "skills", "dated-breaks", "scripts", "dated_breaks.py"),
                                "--offline", os.path.join(tmp, "elsewhere", "tests", "data"), "--today", TODAY, proj)
        self.assertEqual(rc, 0, out)

    def test_naming_the_fixtures_as_the_scan_folder_still_reads_them(self):
        # Only a skill folder met while walking another folder is skipped.
        rc, out, _, _ = cli(SCRIPT, "--offline", DATA, "--today", TODAY, DIRTY)
        self.assertEqual(rc, 1)
        self.assertIn("src/app.py:4", out)


if __name__ == "__main__":
    unittest.main()
