#!/bin/sh
# Prints the gh commands that open each draft listed in .github/GOOD-FIRST-ISSUES/issues.json as an issue of OWNER/REPO.
# Nothing is sent unless --apply is given; without it this script only prints, and gh is not needed.
#   .github/GOOD-FIRST-ISSUES/create-issues.sh OWNER/REPO            print the commands
#   .github/GOOD-FIRST-ISSUES/create-issues.sh OWNER/REPO --apply    run them (needs gh, signed in to an account that may write to OWNER/REPO)
# Create the labels first: .github/create-labels.sh OWNER/REPO [--apply]. Each body is the draft file without its first
# line (the title heading), piped to gh through --body-file -. Run from anywhere; the commands run from the repository root.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
usage='Usage: .github/GOOD-FIRST-ISSUES/create-issues.sh OWNER/REPO [--apply]'
repo=${1:-}
mode=${2:-}
[ "$#" -le 2 ] || { printf '%s\n' "$usage" >&2; exit 2; }
case "$repo" in ''|-*) printf '%s\n' "$usage" >&2; exit 2 ;; esac
if ! printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
  printf '%s\n' "$usage" 'OWNER/REPO must be a GitHub owner and repository name.' >&2; exit 2
fi
case "$mode" in ''|--apply) ;; *) printf '%s\n' "$usage" >&2; exit 2 ;; esac
node=${SCOPEHAVEN_NODE:-node}
command -v "$node" >/dev/null 2>&1 || { printf '%s\n' "create-issues: no Node runtime ($node); set SCOPEHAVEN_NODE" >&2; exit 2; }
# The renderer reads issues.json and prints one shell command per draft, each argument single-quoted for sh.
render='const fs = require("fs"), path = require("path");
const args = process.argv.slice(1); if (args[0] === "--") args.shift();
const [file, repo, root] = args;
const SQ = String.fromCharCode(39);
const q = s => SQ + String(s).split(SQ).join(SQ + "\\" + SQ + SQ) + SQ;
const issues = JSON.parse(fs.readFileSync(file, "utf8"));
if (!Array.isArray(issues) || !issues.length) throw new Error("issues.json must be a non-empty array");
for (const issue of issues) {
  if (typeof issue.title !== "string" || !issue.title || typeof issue.body !== "string" || !Array.isArray(issue.labels) || !issue.labels.length) throw new Error("each issue needs title, body and labels: " + JSON.stringify(issue));
  if (issue.body !== path.basename(issue.body) || !issue.body.endsWith(".md")) throw new Error("body must be a .md file name in this folder: " + issue.body);
  const body = path.posix.join(".github/GOOD-FIRST-ISSUES", issue.body);
  const text = fs.readFileSync(path.join(root, body), "utf8");
  if (!text.startsWith("# " + issue.title + "\n")) throw new Error(body + " must start with its title heading");
  console.log("sed " + q("1{/^# /d;}") + " " + q(body) + " | gh issue create --repo " + q(repo) + " --title " + q(issue.title) + issue.labels.map(l => " --label " + q(l)).join("") + " --body-file -");
}'
commands=$("$node" -e "$render" -- "$here/issues.json" "$repo" "$root")
if [ "$mode" = --apply ]; then
  command -v gh >/dev/null 2>&1 || { printf '%s\n' 'create-issues: gh is not on PATH; nothing was sent' >&2; exit 2; }
  cd "$root"
  eval "$commands"
else
  printf '%s\n' "$commands"
  printf '%s\n' "# Printed only; nothing was sent. Re-run with --apply to open these issues on $repo." >&2
fi
