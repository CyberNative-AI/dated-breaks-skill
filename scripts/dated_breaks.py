#!/usr/bin/env python3
"""dated_breaks.py: list the dated upstream changes a working tree (or a dependency you are about to add) is exposed to.

    python3 scripts/dated_breaks.py [PATH]                    scan a folder (default: .)
    python3 scripts/dated_breaks.py --dep model:gpt-4o        check one thing before you write it
    python3 scripts/dated_breaks.py --dep docker:node:22 --dep runner:macos-14

Reads two public files from the Breakage Calendar (https://cybernative.ai/breakage-calendar/):
entries.json (every date, what replaces it) and check/signatures.json (the search each date publishes),
and runs those searches line by line over your files. Python 3.8+, standard library only.

Privacy: it makes two GET requests with no body and sends nothing from your files. The requests show the
server your IP address, the time and the user agent below. Use --offline DIR to send nothing at all.
Safety: the downloaded searches are matched in a child process that is killed after --time-budget seconds
(default 60), and a folder is read without following symlinks (a symlinked scan folder is refused).
Exit status: 0 nothing found, 1 something found, 2 could not run.
"""
import argparse
import datetime
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request

VERSION = "0.1.0"
BASE = "https://cybernative.ai/breakage-calendar/"
UA = "dated-breaks-skill/%s (+https://github.com/CyberNative-AI/dated-breaks-skill)" % VERSION
MAX_DOWNLOAD = 8 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_FILES = 20000
MAX_HITS = 5  # shown per date; the rest is counted
MAX_DEPTH = 64  # folders deeper than this are not entered
LINE_CAP = 4000  # a longer line is matched on its first LINE_CAP characters
TIME_BUDGET = 60  # seconds the matching child process may run
MAX_SIGNATURES, MAX_PATTERNS, MAX_PATTERN_LEN = 500, 50, 4000  # limits on the downloaded search data

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
             "vendor", "dist", "build", "target", ".next", ".nuxt", "coverage", ".gradle", "Pods", "site-packages"}
SOURCE = re.compile(r"\.(py|pyi|ipynb|js|mjs|cjs|jsx|ts|tsx|go|rb|php|java|kt|kts|scala|cs|rs|swift|ex|exs|sh|bash|zsh|"
                    r"ps1|ya?ml|toml|json|ini|cfg|conf|env|properties|tf|r)$|(^|/)(Dockerfile[^/]*|Makefile|\.env[^/]*)$",
                    re.I)
PROSE = re.compile(r"\.(md|mdx|rst|txt|adoc|html?|xml|ics|csv|svg|po|pot)$|(^|/)(README|CHANGELOG|CHANGES|NEWS|HISTORY|LICENSE)[^/]*$",
                   re.I)

# postgres:latest moves to 19; a digest or a numbered tag does not (the calendar's own rule for that row).
PG = re.compile(r"""(?:image:|FROM)\s*["']?(?:docker\.io/)?(?:library/)?postgres(?::([^\s"'@]+))?(@sha256:[0-9a-f]{64})?(?=[\s"']|$)""")
PG_MOVES = {None, "latest", "alpine", "trixie", "bookworm", "alpine3.24", "alpine3.23"}


def postgres_verdict(line):
    m = PG.search(line)
    if not m:
        return None
    tag, digest = m.groups()
    if digest or (tag and tag[0].isdigit()):
        return None
    return "match" if tag in PG_MOVES else "possible"


# ---- data -----------------------------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch_json(url):
    if not url.startswith("https://"):
        raise RuntimeError("refusing a non-https URL: " + url)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"}, method="GET")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(req, timeout=20) as r:
        body = r.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise RuntimeError("response from %s is larger than %d bytes" % (url, MAX_DOWNLOAD))
    return json.loads(body.decode("utf-8"))


def load_data(offline):
    if offline:
        with open(os.path.join(offline, "entries.json"), encoding="utf-8") as f:
            entries = json.load(f)
        with open(os.path.join(offline, "signatures.json"), encoding="utf-8") as f:
            sigs = json.load(f)
        return entries, sigs
    return fetch_json(BASE + "entries.json"), fetch_json(BASE + "check/signatures.json")


# ---- reading files ------------------------------------------------------------------------------------------------------

_DIR_FLAGS = getattr(os, "O_RDONLY", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = getattr(os, "O_RDONLY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def folder_scan_supported():
    """Folder scans need descriptor-relative, non-following opens (Linux, macOS, BSD). Windows has neither."""
    return (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd and os.listdir in os.supports_fd)


def check_scan_root(path):
    """Return the path to open, or raise ValueError. A scan folder that is itself a symlink is refused."""
    p = path.rstrip("/") or "/"
    last = os.path.basename(p)
    if last in (".", "..") and any(c not in ("", ".", "..") for c in p.split("/")):
        raise ValueError("end the scan folder with its own name, not with '.' or '..' after another folder: %s" % path)
    try:
        st = os.lstat(p)
    except OSError as ex:
        raise ValueError("not a folder: %s (%s)" % (path, ex.strerror))
    if stat.S_ISLNK(st.st_mode):
        raise ValueError("refusing a scan folder that is a symlink: %s (scan the real folder)" % path)
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("not a folder: %s" % path)
    return p


def walk(root, stats, skip=()):
    """Yield (relative path, text) for each regular text file under root. Nothing is followed: every folder and file is opened
    relative to its parent's descriptor with O_NOFOLLOW and judged by fstat of the object actually opened, so a swap to a
    symlink between listing and opening is refused, not read. A folder whose (device, inode) is in skip is not entered."""
    try:
        rfd = os.open(root, _DIR_FLAGS)
    except OSError as ex:
        raise ValueError("cannot open scan folder %s without following a symlink: %s" % (root, ex.strerror))
    try:
        if not stat.S_ISDIR(os.fstat(rfd).st_mode):
            raise ValueError("not a folder: %s" % root)
        yield from _walk_fd(rfd, "", stats, set(skip), 0)
    finally:
        os.close(rfd)


def _walk_fd(dfd, rel, stats, skip, depth):
    if depth >= MAX_DEPTH:
        stats["deep"] += 1
        return
    try:
        names = sorted(os.listdir(dfd))
    except OSError:
        return
    for name in names:
        p = rel + "/" + name if rel else name
        try:
            mode = os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                if name in SKIP_DIRS:
                    continue
                fd = os.open(name, _DIR_FLAGS, dir_fd=dfd)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISDIR(st.st_mode):
                        continue
                    if (st.st_dev, st.st_ino) in skip:
                        stats["self"] += 1
                        continue
                    yield from _walk_fd(fd, p, stats, skip, depth + 1)
                finally:
                    os.close(fd)
                continue
            if not stat.S_ISREG(mode):
                continue  # symlinks, sockets, pipes, devices: never opened
            if stats["files"] >= MAX_FILES:
                stats["stopped"] = True
                return
            fd = os.open(name, _FILE_FLAGS, dir_fd=dfd)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    continue  # swapped for a pipe or device after the listing
                if st.st_size > MAX_FILE:
                    stats["large"] += 1
                    continue
                with os.fdopen(fd, "rb", closefd=False) as f:
                    raw = f.read(MAX_FILE + 1)
            finally:
                os.close(fd)
        except OSError:
            continue  # includes ELOOP when a name was swapped for a symlink
        if len(raw) > MAX_FILE:
            stats["large"] += 1
            continue
        if b"\0" in raw[:8000]:
            continue
        stats["files"] += 1
        yield p, raw.decode("utf-8", "replace")


def synthesize(deps):
    """One line per dependency, in the file a repository would keep it in, so each date's own search runs unchanged."""
    out = {}
    for eco, name in deps:
        if eco == "model":
            out.setdefault("app/models.py", []).append('model = "%s"' % name)
        elif eco == "docker":
            out.setdefault("compose.yaml", []).append("    image: " + name)
        elif eco == "runner":
            out.setdefault(".github/workflows/deps.yml", []).append("    runs-on: " + name)
        elif eco == "action":
            out.setdefault(".github/workflows/deps.yml", []).append("      - uses: " + name)
        elif eco == "brew":
            out.setdefault("Brewfile", []).append('brew "%s"' % name)
        elif eco == "npm":
            n, _, v = name.rpartition("@") if "@" in name[1:] else (name, "", "*")
            out.setdefault("package.json", []).append('    "%s": "%s",' % (n, v or "*"))
        elif eco == "pypi":
            out.setdefault("requirements.txt", []).append(name)
    return [(p, "\n".join(lines) + "\n") for p, lines in out.items()]


ECOS = ("model", "docker", "runner", "action", "brew", "npm", "pypi")


def parse_dep(raw):
    eco, sep, name = raw.strip().partition(":")
    eco = {"image": "docker", "container": "docker", "runs-on": "runner", "homebrew": "brew", "pip": "pypi"}.get(eco.lower(), eco.lower())
    if not sep or eco not in ECOS or not name or not re.fullmatch(r"[\x20-\x7e]{1,200}", name) or re.search(r"[\"'`\\]", name):
        raise ValueError("--dep wants ECOSYSTEM:NAME with ECOSYSTEM one of %s (for example model:gpt-4o); got %r" % (", ".join(ECOS), raw))
    return eco, name.strip()


# ---- matching (the same rules as the calendar's own page) ---------------------------------------------------------------

def file_test(spec, sigs):
    if spec == "source":
        return lambda p: bool(SOURCE.search(p))
    if spec == "any":
        return lambda p: True
    pat = re.compile(sigs["workflow"] if spec == "workflow" else spec)
    return pat.search


def scan(files, sigs, stats=None):
    found = []
    stats = stats if stats is not None else {}
    for s in sigs["signatures"]:
        want = file_test(s["files"], sigs)
        pats = [re.compile(p) for p in s["patterns"]]
        needs = re.compile(s["needs"]) if s.get("needs") else None
        code, prose, more = [], [], 0
        kind = None if s["kind"] == "postgres" else s["kind"]
        for path, text in files:
            if not want(path):
                continue
            if s["files"] == "source" and PROSE.search(path):
                continue
            if needs and not needs.search(text):
                continue
            bucket = prose if PROSE.search(path) else code
            for i, line in enumerate(re.split(r"\r?\n", text)):
                if len(line) > LINE_CAP:
                    stats["long"] = stats.get("long", 0) + 1
                    line = line[:LINE_CAP]
                if s["kind"] == "postgres":
                    v = postgres_verdict(line)
                    hit = v is not None
                    if hit:
                        kind = "match" if (kind == "match" or v == "match") else "possible"
                else:
                    hit = any(p.search(line) for p in pats)
                if not hit:
                    continue
                if len(bucket) < 25:
                    bucket.append({"path": path, "line": i + 1, "text": line.strip()[:160]})
                else:
                    more += 1
        if not code and not prose:
            continue
        if kind == "match" and not code:
            kind = "mention"  # only documents name it: a mention, not code that sends it
        found.append({"row": s["row"], "kind": kind, "hits": code + prose, "more": more})
    return found


# ---- the downloaded searches: validated, then matched in a child process that can be killed --------------------------------

def validate_sigs(sigs):
    """The search data comes from the network, so check its shape and size before any of it reaches re.compile."""
    def bad(why):
        raise ValueError("refusing the downloaded search data: " + why)
    if not isinstance(sigs, dict) or not isinstance(sigs.get("signatures"), list):
        bad("no signatures list")
    if len(sigs["signatures"]) > MAX_SIGNATURES:
        bad("more than %d signatures" % MAX_SIGNATURES)
    if not isinstance(sigs.get("workflow"), str) or len(sigs["workflow"]) > MAX_PATTERN_LEN:
        bad("workflow pattern missing or too long")
    for s in sigs["signatures"]:
        if not isinstance(s, dict) or not all(isinstance(s.get(k), str) for k in ("row", "kind", "files")):
            bad("a signature lacks row, kind or files")
        pats = s.get("patterns")
        if not isinstance(pats, list) or len(pats) > MAX_PATTERNS or not all(isinstance(x, str) and len(x) <= MAX_PATTERN_LEN for x in pats):
            bad("a signature has no patterns, too many, or one longer than %d characters" % MAX_PATTERN_LEN)
        if len(s["files"]) > MAX_PATTERN_LEN or (s.get("needs") is not None and (not isinstance(s["needs"], str) or len(s["needs"]) > MAX_PATTERN_LEN)):
            bad("a file selector is not text or is too long")
    return sigs


def run_job(job):
    """Everything that evaluates a downloaded regex or reads project files. It runs in the child process."""
    sigs = validate_sigs(job["sigs"])
    stats = {"files": 0, "large": 0, "stopped": False, "deep": 0, "self": 0, "long": 0}
    files = synthesize([tuple(d) for d in job["deps"]]) if job["deps"] else []
    stats["files"] = len(files)
    if job["root"] is not None:
        files += list(walk(job["root"], stats, [tuple(x) for x in job["skip"]]))
    try:
        found = scan(files, sigs, stats)
    except re.error as ex:
        raise ValueError("refusing the downloaded search data: a pattern does not compile (%s)" % ex)
    return {"found": found, "stats": stats}


def run_bounded(job, budget):
    """Run run_job in a fresh interpreter and kill it when the budget runs out: a regex cannot be interrupted from inside."""
    if not sys.executable:
        raise ValueError("cannot start the matching process: no Python executable path")
    try:
        r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--worker"], input=json.dumps(job).encode("utf-8"),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=budget)
    except subprocess.TimeoutExpired:
        raise ValueError("matching took longer than the %d s time budget and was stopped; nothing is reported. "
                         "The downloaded searches or a file in the folder may be adverse; scan a smaller folder or raise --time-budget" % budget)
    try:
        out = json.loads(r.stdout.decode("utf-8"))
    except ValueError:
        raise ValueError("the matching process failed (exit %s): %s" % (r.returncode, r.stderr.decode("utf-8", "replace").strip()[-300:]))
    if "error" in out:
        raise ValueError(out["error"])
    return out["found"], out["stats"]


def worker_main():
    try:
        out = run_job(json.loads(sys.stdin.buffer.read().decode("utf-8")))
    except (ValueError, OSError, re.error, RecursionError) as ex:
        out = {"error": str(ex)}
    sys.stdout.write(json.dumps(out))
    return 0


# ---- report -------------------------------------------------------------------------------------------------------------

def absolute(href):
    return "https://cybernative.ai" + href if href and href.startswith("/") else href


def replacement(e):
    fix = e.get("fix") or {}
    if fix.get("kind") in ("tested", "guide") and fix.get("text"):
        t = fix["text"].strip()
        return t if len(t) <= 420 else t[:417].rsplit(" ", 1)[0] + "..."
    for sent in re.split(r"(?<=[.!?])\s+", e.get("what", "")):
        if re.search(r"replacement|replaced by|moves? to|switch to", sent, re.I):
            return sent.strip()
    return fix.get("label") or "No replacement is listed; read the source below."


def build_report(found, entries, today):
    by_id = {e["id"]: e for e in entries["entries"]}
    rows = []
    for f in found:
        e = by_id.get(f["row"])
        if not e:
            continue
        d = datetime.date.fromisoformat(e["date"])
        fix = e.get("fix") or {}
        rows.append({
            "id": e["id"], "date": e["date"], "dateEnd": e.get("dateEnd"), "daysLeft": (d - today).days,
            "result": f["kind"], "title": e["title"], "replacement": replacement(e),
            "fixHref": absolute(fix.get("href")), "fixTested": fix.get("kind") == "tested",
            "source": (e.get("sources") or [{}])[0].get("href"), "sourceChecked": (e.get("sources") or [{}])[0].get("checkedAt"),
            "hits": f["hits"][:MAX_HITS], "moreHits": max(0, len(f["hits"]) - MAX_HITS) + f["more"],
        })
    rows.sort(key=lambda r: (r["date"], r["id"]))
    return rows


LABEL = {"match": "HITS", "possible": "MAY HIT", "mention": "MENTIONED"}


def render(rows, entries, sigs, stats, what):
    out = []
    if not rows:
        out.append("No dated breaks found in %s (%d text files read)." % (what, stats["files"]))
    else:
        out.append("%d dated break%s in %s:" % (len(rows), "" if len(rows) == 1 else "s", what))
        for r in rows:
            when = r["date"] + (" to " + r["dateEnd"] if r["dateEnd"] else "")
            dl = r["daysLeft"]
            rel = "in effect since %d days ago" % -dl if dl < 0 else "today" if dl == 0 else "in %d days" % dl
            out += ["", "%s  (%s)  %s  %s" % (when, rel, LABEL.get(r["result"], r["result"]), r["title"])]
            for h in r["hits"]:
                out.append("    found:    %s:%d  %s" % (h["path"], h["line"], h["text"]))
            if r["moreHits"]:
                out.append("    found:    ... and %d more lines" % r["moreHits"])
            out.append("    replace:  " + r["replacement"])
            if r["fixHref"]:
                out.append("    fix:      %s%s" % (r["fixHref"], " (tested by the calendar's authors)" if r["fixTested"] else ""))
            if r["source"]:
                out.append("    source:   %s (checked %s)" % (r["source"], r["sourceChecked"]))
        out += ["", "A model ID or version can also be set outside the files (an environment variable, a dashboard, a database);",
                "HITS and MAY HIT mean the files show it, not that nothing else does. Confirm each date on the source page."]
    blind = len(sigs.get("blind", {}))
    out += ["", "Data: %s, updated %s. %d dates in it cannot be seen from files at all (a runtime, a server, a certificate)." % (
        entries.get("page", BASE), entries.get("updated", "?"), blind)]
    lim = []
    if stats.get("stopped"):
        lim.append("stopped after %d files" % MAX_FILES)
    if stats.get("large"):
        lim.append("%d files over 1 MB skipped" % stats["large"])
    if stats.get("long"):
        lim.append("%d lines over %d characters matched on their first %d" % (stats["long"], LINE_CAP, LINE_CAP))
    if stats.get("deep"):
        lim.append("%d folders deeper than %d levels not entered" % (stats["deep"], MAX_DEPTH))
    if stats.get("self"):
        lim.append("this skill's own folder was not scanned")
    if lim:
        out.append("Limits: %s." % ", ".join(lim))
    return "\n".join(out)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--worker"]:
        return worker_main()
    ap = argparse.ArgumentParser(description="List dated upstream breaks a working tree is exposed to.", epilog=__doc__.split("Privacy:")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=None, help="folder to scan (default: . unless --dep is given)")
    ap.add_argument("--dep", action="append", default=[], metavar="ECO:NAME", help="check one dependency without a folder: " + ", ".join(ECOS))
    ap.add_argument("--within", type=int, metavar="DAYS", help="only dates already in effect or at most DAYS away")
    ap.add_argument("--offline", metavar="DIR", help="read DIR/entries.json and DIR/signatures.json instead of fetching")
    ap.add_argument("--today", metavar="YYYY-MM-DD", help="count days from this date (default: today, UTC)")
    ap.add_argument("--time-budget", type=int, default=TIME_BUDGET, metavar="SECONDS", help="stop the matching after this long (default %d)" % TIME_BUDGET)
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--version", action="version", version="dated_breaks " + VERSION)
    a = ap.parse_args(argv)
    try:
        today = datetime.date.fromisoformat(a.today) if a.today else datetime.datetime.now(datetime.timezone.utc).date()
        deps = [parse_dep(d) for d in a.dep]
        if not 1 <= a.time_budget <= 600:
            raise ValueError("--time-budget wants 1 to 600 seconds")
        root = None
        if a.path is not None or not deps:
            if not folder_scan_supported():
                raise ValueError("folder scans need Linux, macOS or BSD (this system cannot open files without following symlinks); "
                                 "--dep and --offline still work")
            root = check_scan_root(a.path or ".")
        entries, sigs = load_data(a.offline)
        validate_sigs(sigs)
        skill = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        sst = os.stat(skill)
        job = {"sigs": sigs, "deps": deps, "root": root, "skip": [[sst.st_dev, sst.st_ino]]}
        found, stats = run_bounded(job, a.time_budget)
        what = ", ".join("%s:%s" % d for d in deps)
        if root is not None:
            what = (what + " and " if what else "") + ("folder " + os.path.abspath(root))
        rows = build_report(found, entries, today)
    except (ValueError, OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as ex:
        print("dated_breaks: %s" % ex, file=sys.stderr)
        return 2
    except Exception as ex:  # a malformed download must end as "could not run", never as a traceback with exit status 1
        print("dated_breaks: unexpected %s: %s" % (type(ex).__name__, ex), file=sys.stderr)
        return 2
    if a.within is not None:
        rows = [r for r in rows if r["daysLeft"] <= a.within]
    if a.json:
        print(json.dumps({"checked": what, "today": today.isoformat(), "calendarUpdated": entries.get("updated"), "findings": rows}, indent=2))
    else:
        print(render(rows, entries, sigs, stats, what))
    return 1 if rows else 0


if __name__ == "__main__":
    sys.exit(main())
