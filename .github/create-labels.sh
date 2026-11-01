#!/bin/sh
# Prints the gh commands that create or update the labels in .github/labels.json on OWNER/REPO.
# Nothing is sent unless --apply is given; without it this script only prints, and gh is not needed.
#   .github/create-labels.sh OWNER/REPO            print the commands
#   .github/create-labels.sh OWNER/REPO --apply    run them (needs gh, signed in to an account that may write to OWNER/REPO)
# --force makes each command an update when the label already exists, so re-running is safe.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
usage='Usage: .github/create-labels.sh OWNER/REPO [--apply]'
repo=${1:-}
mode=${2:-}
[ "$#" -le 2 ] || { printf '%s\n' "$usage" >&2; exit 2; }
case "$repo" in ''|-*) printf '%s\n' "$usage" >&2; exit 2 ;; esac
if ! printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
  printf '%s\n' "$usage" 'OWNER/REPO must be a GitHub owner and repository name.' >&2; exit 2
fi
case "$mode" in ''|--apply) ;; *) printf '%s\n' "$usage" >&2; exit 2 ;; esac
node=${SCOPEHAVEN_NODE:-node}
command -v "$node" >/dev/null 2>&1 || { printf '%s\n' "create-labels: no Node runtime ($node); set SCOPEHAVEN_NODE" >&2; exit 2; }
# The renderer reads labels.json and prints one shell command per label, each argument single-quoted for sh.
render='const fs = require("fs");
const args = process.argv.slice(1); if (args[0] === "--") args.shift();
const [file, repo] = args;
const SQ = String.fromCharCode(39);
const q = s => SQ + String(s).split(SQ).join(SQ + "\\" + SQ + SQ) + SQ;
const labels = JSON.parse(fs.readFileSync(file, "utf8"));
if (!Array.isArray(labels) || !labels.length) throw new Error("labels.json must be a non-empty array");
for (const label of labels) {
  if (typeof label.name !== "string" || !/^[0-9a-f]{6}$/.test(label.color) || typeof label.description !== "string") throw new Error("label needs name, 6-hex color and description: " + JSON.stringify(label));
  console.log("gh label create " + q(label.name) + " --repo " + q(repo) + " --color " + q(label.color) + " --description " + q(label.description) + " --force");
}'
commands=$("$node" -e "$render" -- "$root/.github/labels.json" "$repo")
if [ "$mode" = --apply ]; then
  command -v gh >/dev/null 2>&1 || { printf '%s\n' 'create-labels: gh is not on PATH; nothing was sent' >&2; exit 2; }
  cd "$root"
  eval "$commands"
else
  printf '%s\n' "$commands"
  printf '%s\n' "# Printed only; nothing was sent. Re-run with --apply to create these labels on $repo." >&2
fi
