# dated-breaks-skill

An agent skill that makes a coding agent check the model IDs, image tags, runners and versions it is about to write against a public calendar of dated upstream breaks, and say **what expires when and what replaces it**.

```
$ python3 scripts/dated_breaks.py tests/fixtures/dirty      # excerpt of the real output
3 dated breaks in folder .../tests/fixtures/dirty:

2027-01-14  (in 61 days)  HITS  OpenAI removes GPT-4o, GPT-4o mini, GPT-4.1 and GPT-4.1 mini from its API
    found:    src/app.py:4  reply = client.chat.completions.create(model="gpt-4o", messages=[...
    replace:  The recommended replacement is gpt-6-luna.
    fix:      https://developers.openai.com/api/docs/deprecations
    source:   https://developers.openai.com/api/docs/deprecations (checked 2026-10-18)

2027-04-30  (in 167 days)  MAY HIT  Node 22 reaches end of life, and the node:22 images stop getting updates
    found:    Dockerfile:1  FROM node:22
    replace:  Move to Node 24, supported until 30 April 2028, or Node 26, ...
```

## The two dates to know first

Read from [OpenAI's deprecations page](https://developers.openai.com/api/docs/deprecations) on 2026-11-13:

- **2026-12-11**: `gpt-5`, `gpt-5-mini`, `gpt-5-nano`, `gpt-5-pro`, `o3` and `o3-pro`. OpenAI lists `gpt-6.1-sol`, `gpt-6.1-terra` and `gpt-6-luna` as replacements (which one depends on the model).
- **2027-01-14**: `gpt-4o`, `gpt-4o-mini`, `gpt-4.1` and `gpt-4.1-mini`. OpenAI lists the dated snapshots and recommends `gpt-6-luna`. The notice does not say whether the bare names keep working.

## Install

It is a folder with a `SKILL.md`. Put it where your agent reads skills, for example for Claude Code:

```
git clone https://github.com/CyberNative-AI/dated-breaks-skill ~/.claude/skills/dated-breaks
```

For other agents that read `SKILL.md` folders, copy the same folder into their skills directory. The script works on its own too; it needs Python 3.8 or later and nothing else.

## Use

```
python3 scripts/dated_breaks.py .                      # scan a working tree
python3 scripts/dated_breaks.py --dep model:gpt-4o     # check one value before you write it
python3 scripts/dated_breaks.py . --within 60 --json   # next 60 days, as JSON
```

`--dep` takes `model`, `docker`, `runner`, `action`, `brew`, `npm` or `pypi`. Exit status: 0 nothing found, 1 something found, 2 could not run.

Each result is `HITS` (the date's own published search found the line), `MAY HIT` (the files use what the date affects; only some setups break) or `MENTIONED` (only a document names it).

## Where the data comes from

The [Breakage Calendar](https://cybernative.ai/breakage-calendar/) publishes two files: [`entries.json`](https://cybernative.ai/breakage-calendar/entries.json) (every date, its source and what replaces it) and [`check/signatures.json`](https://cybernative.ai/breakage-calendar/check/signatures.json) (the search each date publishes). The script runs those searches line by line over your files. It adds no data of its own.

## Privacy

The script makes two GET requests with no body, with the user agent `dated-breaks-skill/0.1.0 (+https://github.com/CyberNative-AI/dated-breaks-skill)`, and refuses redirects and non-HTTPS URLs. The requests show the server your IP address and the time. **Nothing from your files is sent.** `--offline DIR` (with `entries.json` and `signatures.json` in it) sends nothing at all. It reads files; it never writes to your project and never runs or installs anything from it. The only process it starts is a second copy of the same Python interpreter running this same script, which does the matching (see the first limit below).

## Limits

- It sees what files show. A model set by an environment variable, a dashboard or a database row is invisible to it, and so is a library's own default model. Clean output means "no file shows it", not "safe".
- **The searches are bounded.** The searches come from the calendar's published data and are checked for shape and size (at most 500 signatures, 50 patterns each, 4,000 characters per pattern) before use. The matching runs in a child process that is stopped after 60 seconds (`--time-budget`, 1 to 600); then the script prints why on stderr, reports nothing and exits 2. A line longer than 4,000 characters is matched on its first 4,000 characters, and the text output (not `--json`) says how many such lines there were.
- **Nothing is followed.** A scan folder that is itself a symlink is refused (scan the real folder). Inside the folder every folder and file is opened without following links and is read only if the object actually opened is a regular file, so a name swapped for a symlink or a pipe after it was listed is skipped, not read. Pipes, sockets and devices are skipped before anything is read (a file replaced by a pipe after listing may be opened without blocking, then rejected). A folder scan needs Linux, macOS or BSD; on Windows it exits 2. On Windows only dependency checks work: `--dep ...` (with `--offline DIR` if you want no network); `--offline DIR` on its own still attempts a folder scan and exits 2.
- **It skips its own folder** when the skill is installed inside the project you scan (for example `.claude/skills/dated-breaks`), so its test fixtures are never reported. Folders deeper than 64 levels are not entered.
- It skips `.git`, `node_modules`, virtual environments, `vendor`, build output, symlinks, binary files and files over 1 MB.
- Replacement names come from the calendar and move; check the linked source before you change anything.
- Dates the calendar does not cover are not checked.

## Test

```
python3 -m unittest discover -s tests -v
```

The tests run offline on a pinned copy of six real calendar rows. A fixture containing `gpt-4o` and `node:22` must be flagged on both; a clean fixture (a current model, `node:24-slim`, a comment and a test file that name `gpt-4o`) must produce nothing. Further tests cover a downloaded pattern that never finishes (the process is stopped at the time budget), invalid or oversized downloaded data (exit 2), adverse input to the live Node 22 search, symlinked scan folders in every spelling, files and folders swapped for symlinks or pipes after they were listed, and a copy of the skill installed inside the scanned project (its fixtures are not reported).

## About

Prepared by CyberNative AI LLC, an AI-run company, using AI agents. Contact: hello@cybernative.ai. Issues and pull requests are welcome. MIT licence.
