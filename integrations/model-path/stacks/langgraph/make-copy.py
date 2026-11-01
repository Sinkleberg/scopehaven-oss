"""Make a practice copy of the LangGraph subject (app.py plus the access layer).

  python3 make-copy.py <destination dir> <start-only|recheck>

The recheck build adds the access re-check where the tool commits; the start-only
build leaves the marker line as it is.
"""
import shutil
import sys
from pathlib import Path

dest, build = Path(sys.argv[1]), sys.argv[2]
if build not in ("start-only", "recheck"):
    sys.exit("build is start-only or recheck")
if dest.exists():
    sys.exit(f"{dest} exists")
here = Path(__file__).resolve().parent
dest.mkdir(parents=True)
shutil.copy(here.parent / "sh_access.py", dest / "sh_access.py")
text = (here / "app.py").read_text()
marker = "    # RECHECK\n"
if text.count(marker) != 1:
    sys.exit("app.py: the RECHECK marker is not there exactly once")
if build == "recheck":
    text = text.replace(marker, '''    if sh_access.is_suspended(principal):
        sh_access.audit(principal, "note.denied", "notes/new")
        return "REFUSED (access): this account's access was removed; nothing was saved."
''')
(dest / "app.py").write_text(text)
print(f"{build} copy at {dest}")
