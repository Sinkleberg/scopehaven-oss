"""Make a practice copy of openai-cs-agents' python backend with the MIDTASK-ANY access layer.

  python3 make-copy.py <source python-backend> <destination dir> <start-only|recheck>

The source is read only; the destination must not exist. The copy is the upstream
backend plus sh_access.py and three edits, each an exact text replacement that must
match once (a changed upstream refuses rather than patching the wrong place):
  main.py   /chatkit takes the user's bearer token and refuses a suspended user when the
            task starts (both builds); POST /sh-admin/suspend lets the admin suspend a user
  tools.py  update_seat records that it ran; the recheck build refuses a suspended user
            there; a committed change is recorded as seat.update
The copy is run with the source's own virtual environment (not copied).
"""
import shutil
import sys
from pathlib import Path

src, dest, build = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
if build not in ("start-only", "recheck"):
    sys.exit("build is start-only or recheck")
if dest.exists():
    sys.exit(f"{dest} exists")
shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".*"))
shutil.copy(Path(__file__).resolve().parent.parent / "sh_access.py", dest / "sh_access.py")


def edit(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        sys.exit(f"{path.name}: the expected upstream text is not there exactly once")
    path.write_text(text.replace(old, new))


main = dest / "main.py"
edit(main, '@app.post("/chatkit")\n', '''import sh_access


@app.post("/sh-admin/suspend")
async def sh_admin_suspend(request: Request) -> Response:
    if sh_access.principal_of(request.headers.get("authorization")) != sh_access.ADMIN:
        return Response(status_code=403)
    body = await request.json()
    principal = str(body.get("principal", ""))[:80]
    sh_access.suspend(principal, by=sh_access.ADMIN)
    return Response(content='{"suspended": true}', media_type="application/json")


@app.post("/chatkit")
''')
edit(main, '''    payload = await request.body()
    result = await server.process(payload, {"request": request})''', '''    principal = sh_access.principal_of(request.headers.get("authorization"))
    if principal != sh_access.USER:
        return Response(status_code=401)
    # Authorized when the task starts.
    if sh_access.is_suspended(principal):
        return Response(status_code=403)
    payload = await request.body()
    result = await server.process(payload, {"request": request, "principal": principal})''')

recheck = '''    if sh_access.is_suspended(principal):
        sh_access.audit(principal, "seat.denied", f"seat/{confirmation_number}")
        return "REFUSED (access): this account's access was removed; no change was made."
''' if build == "recheck" else ""
tools = dest / "airline" / "tools.py"
edit(tools, "from .context import AirlineAgentChatContext\n", "import sh_access\n\nfrom .context import AirlineAgentChatContext\n")
edit(tools, '''    """Update the seat for a given confirmation number."""
    apply_itinerary_defaults(context.context.state)
    context.context.state.confirmation_number = confirmation_number
    context.context.state.seat_number = new_seat
    assert context.context.state.flight_number is not None, "Flight number is required"
''', '''    """Update the seat for a given confirmation number."""
    principal = context.context.request_context.get("principal")
    sh_access.audit(principal, "tool.invoked", f"seat/{confirmation_number}")
''' + recheck + '''    apply_itinerary_defaults(context.context.state)
    context.context.state.confirmation_number = confirmation_number
    context.context.state.seat_number = new_seat
    assert context.context.state.flight_number is not None, "Flight number is required"
    sh_access.audit(principal, "seat.update", f"seat/{confirmation_number}")
''')
print(f"{build} copy at {dest}")
