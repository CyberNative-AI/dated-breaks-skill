---
name: dated-breaks
description: Before writing or upgrading code that names an AI model ID, a container image tag, a CI runner, a runtime version or a package, check it against a public calendar of dated upstream shutdowns and removals, and report what expires when and what replaces it. Use when adding or changing a model ID such as gpt-4o or claude-sonnet-4-5, a Docker FROM line, a GitHub Actions runs-on label, or when asked whether a repository depends on something that is about to stop working.
---

# Dated breaks

Your training data is older than the break. A model ID can be shut down in weeks, an image tag can move to a new major version, a CI runner can be retired, and none of that is in what you remember. This skill checks the thing you are about to write against the [Breakage Calendar](https://cybernative.ai/breakage-calendar/), a public list of dated upstream changes, each with its source.

## The two dates that reach the most code (provider page read 2026-11-13)

Check these first. They are on [OpenAI's deprecations page](https://developers.openai.com/api/docs/deprecations).

| Shutdown | Models | The provider's listed replacement |
|---|---|---|
| **2026-12-11** | `gpt-5`, `gpt-5-mini`, `gpt-5-nano`, `gpt-5-pro`, `o3`, `o3-pro` (short names and dated snapshots are both listed) | `gpt-6.1-sol` for `gpt-5` and `o3`; `gpt-6.1-terra` for `gpt-5-mini`; `gpt-6-luna` for `gpt-5-nano`; `gpt-6.1-sol` with `reasoning.mode: pro` (Responses API) for `gpt-5-pro` and `o3-pro` |
| **2027-01-14** | `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`, `gpt-4.1-mini`. The provider lists the dated snapshots (`gpt-4o-2024-08-06`, `gpt-4o-2024-11-20`, `gpt-4o-mini-2024-07-18`, `gpt-4.1-2025-04-14`, `gpt-4.1-mini-2025-04-14`); it does not say whether the bare names keep working, and every snapshot they point to is on the list | `gpt-6-luna` |

Replacement names move. If the calendar's text and the provider's page disagree, the provider's page wins; say so to the user.

## When to run it

1. **Before you write a model ID, an image tag or a runner label**, check that one value:

   ```
   python3 scripts/dated_breaks.py --dep model:gpt-4o
   python3 scripts/dated_breaks.py --dep docker:node:22 --dep runner:macos-14
   ```

   Ecosystems: `model`, `docker`, `runner`, `action`, `brew`, `npm`, `pypi`.

2. **Before you finish a change or open a pull request**, scan the working tree (the folder you are in):

   ```
   python3 scripts/dated_breaks.py .
   ```

   Add `--within 60` to see only what is already in effect or lands in the next 60 days. Add `--json` to read the result as data.

Needs Python 3.8 or later and nothing else. The script fetches two public files over HTTPS (no key, no account) and sends nothing from the project. `--offline DIR` reads local copies instead.

## What you get back

For each date the files show: the date and the days left, `HITS` (the calendar's own search found the line), `MAY HIT` (the files use what the date affects and only some setups break) or `MENTIONED` (only prose names it), the file and line, what replaces it, and the source page. Exit status is 0 when nothing was found, 1 when something was, 2 when the script could not run.

## What to do with it

- **Tell the user, with the date.** "`src/llm.py:12` sends `gpt-4o`; OpenAI shuts it down on 2027-01-14 and lists `gpt-6-luna` as the replacement; source: <link>."
- **Do not swap a model silently.** A replacement model changes output, price and limits. Propose the change, name the replacement the source page lists, and let the user choose.
- **A new model ID you were about to write is not a finding to ignore.** Choose a listed replacement or ask which the user wants.
- **Clean output is not a clearance.** A model can be set by an environment variable, a dashboard or a database row that no file shows. Say what you checked (folder, files read) and what you could not see.
- **Read the source before you quote a replacement.** The row links the provider's own notice.

## Limits

The scan reads text files up to 1 MB, skips `.git`, `node_modules`, virtual environments, `vendor`, build output, symlinks and this skill's own folder, and does not read installed packages. It refuses a scan folder that is a symlink (scan the real folder) and, on Windows, a folder scan at all (`--dep` still works). The matching stops after 60 seconds and the script then exits 2 with a reason; a line over 4,000 characters is matched on its first 4,000. A library that sends a default model when your code passes none is invisible to a scan of your own files; the calendar row for that date says how to search the installed package.
