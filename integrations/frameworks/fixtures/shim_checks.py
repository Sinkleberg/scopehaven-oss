"""Checks of the shipped Python shim (adapters/shim.py), run by shim.test.mjs. Prints one JSON object:
{check: {"ok": bool, "detail": ...}}. Each check exercises one property with an allowed and a
forbidden case. Standard library only; no network.

usage: python3 -I -B shim_checks.py
"""
import asyncio
import collections
import dataclasses
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters"))
import shim  # noqa: E402


class SlowWriter:
    """A stream whose writes land in small pieces with a thread switch between them, the way a
    large line can reach a pipe in several writes."""

    def __init__(self, piece=7):
        self.parts, self.piece = [], piece

    def write(self, text):
        for i in range(0, len(text), self.piece):
            self.parts.append(text[i:i + self.piece])
            time.sleep(0)

    def flush(self):
        pass

    def lines(self):
        return [line for line in "".join(self.parts).split("\n") if line]


def records(writer):
    return [json.loads(line)["record"] for line in writer.lines()]


def check(fn):
    try:
        ok, detail = fn()
    except Exception as error:
        ok, detail = False, f"{type(error).__name__}: {error}"
    return {"ok": bool(ok), "detail": detail}


def channel_lines():
    # Allowed: every line is whole JSON. Forbidden: two threads' pieces interleaving inside a line.
    writer = SlowWriter()
    channel = shim.Channel(out=writer)
    threads = [threading.Thread(target=lambda n=n: [channel.send({"type": "tool", "record": {"n": n, "i": i, "pad": "x" * 60}}) for i in range(25)]) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines, bad = writer.lines(), 0
    for line in lines:
        try:
            json.loads(line)
        except ValueError:
            bad += 1
    return len(lines) == 150 and bad == 0, {"lines": len(lines), "unparsable": bad}


def ledger_order():
    # A call that starts first and ends last: its record is written second, so it carries 2.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), None)
    inside, release = threading.Event(), threading.Event()
    slow = ledger.wrap(lambda: inside.set() or release.wait(5) and "slow", "slow")
    fast = ledger.wrap(lambda: "fast", "fast")
    a = threading.Thread(target=slow)
    a.start()
    inside.wait(5)
    fast()
    release.set()
    a.join()
    got = [(r["seq"], r["tool"]) for r in records(writer)]
    return got == [(1, "fast"), (2, "slow")], got


class Unprintable:
    def __repr__(self):
        raise RuntimeError("no repr")


def unfinished():
    # A call still running is counted until its record is written; a result that cannot be
    # captured still leaves its record, so no call goes missing.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), None)
    inside, release = threading.Event(), threading.Event()
    hold = ledger.wrap(lambda: inside.set() or release.wait(5) and "held", "hold")
    odd = ledger.wrap(lambda: Unprintable(), "odd")
    a = threading.Thread(target=hold)
    a.start()
    inside.wait(5)
    during = ledger.unfinished()
    release.set()
    a.join()
    odd()
    got = records(writer)
    ok = during == 1 and ledger.unfinished() == 0 and [r["tool"] for r in got] == ["hold", "odd"] and got[1]["result"] == {"unrecordable": "RuntimeError"}
    return ok, {"during": during, "after": ledger.unfinished(), "records": [r["tool"] for r in got], "odd": got[1].get("result") if len(got) > 1 else None}


class SlowFault(dict):
    """A fault plan whose tool name is slow to read, so two first calls overlap in the decision."""

    def __getitem__(self, key):
        if key == "tool":
            time.sleep(0.05)
        return super().__getitem__(key)


def fault_once():
    # Two concurrent first calls to the planned tool: exactly one fault, and it is the tool's first record.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), SlowFault(tool="refund", kind="timeout", message="upstream timed out"))
    refund = ledger.wrap(lambda: "refunded", "refund")

    def go():
        try:
            refund()
        except TimeoutError:
            pass
    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    got = [r["status"] for r in records(writer)]
    return got == ["fault-injected", "returned"], got


def fault_reset():
    # Allowed: the body runs and returns, its record is marked and carries the result, and the
    # agent gets a connection reset instead; a later call runs normally. Forbidden: a first call
    # that raises being marked (nothing was committed), or the lost result counting as the last one.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "refund", "kind": "reset-after-commit", "message": "connection reset by peer"})
    effects = []
    refund = ledger.wrap(lambda amount: effects.append(amount) or {"refunded": amount}, "refund")
    try:
        refund(40)
        reset = False
    except ConnectionResetError as error:
        reset = str(error) == "connection reset by peer"
    last_after_reset = ledger.last_result
    again = refund(40)
    got = records(writer)
    shape = [(r["tool"], r["status"], r.get("fault"), r.get("result")) for r in got]
    ok_main = reset and effects == [40, 40] and last_after_reset is None and again == {"refunded": 40} and shape == [("refund", "returned", "reset-after-commit", {"refunded": 40}), ("refund", "returned", None, {"refunded": 40})]
    # A first call that raises spends the fault: one plain exception record, and the next call is not reset.
    writer2 = SlowWriter(piece=4096)
    ledger2 = shim.Ledger(shim.Channel(out=writer2), {"tool": "refund", "kind": "reset-after-commit", "message": "reset"})
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("card declined")
        return "ok"
    wrapped = ledger2.wrap(flaky, "refund")
    try:
        wrapped()
    except ValueError:
        pass
    second = wrapped()
    shape2 = [(r["status"], r.get("fault")) for r in records(writer2)]
    ok_raised = second == "ok" and shape2 == [("exception", None), ("returned", None)] and ledger.unfinished() == 0 and ledger2.unfinished() == 0
    return ok_main and ok_raised, {"reset": reset, "effects": effects, "records": shape, "raisedFirst": shape2}


def fault_duplicate():
    # Allowed: the body runs twice with the same arguments, both records are written together, the
    # agent gets the first result (the duplicate's with seen 'second'), sync and async. Forbidden: a
    # duplicate after a first delivery that raised, or a call to another tool landing between the
    # two records while the duplicate runs.
    out = {}
    for seen in ("first", "second"):
        writer = SlowWriter(piece=4096)
        plan = {"tool": "refund", "kind": "duplicate-delivery", **({"seen": seen} if seen == "second" else {})}
        ledger = shim.Ledger(shim.Channel(out=writer), plan)
        n = []
        refund = ledger.wrap(lambda amount: n.append(amount) or f"r{len(n)}", "refund")
        got = refund(40)
        out[seen] = {"returned": got, "last": ledger.last_result, "runs": len(n), "records": [(r["seq"], r["status"], r.get("fault"), r.get("seen"), r["result"], r["args"]) for r in records(writer)]}
    args = {"args": [40], "kwargs": {}}
    ok_seen = out["first"] == {"returned": "r1", "last": "r1", "runs": 2, "records": [(1, "returned", None, None, "r1", args), (2, "returned", "duplicate-delivery", "first", "r2", args)]} \
        and out["second"] == {"returned": "r2", "last": "r2", "runs": 2, "records": [(1, "returned", None, None, "r1", args), (2, "returned", "duplicate-delivery", "second", "r2", args)]}

    bookings = []

    async def booking(code):
        await asyncio.sleep(0)
        bookings.append(code)
        return f"booked {code} #{len(bookings)}"
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "booking", "kind": "duplicate-delivery"})
    got_async = asyncio.run(ledger.wrap(booking, "booking")("B1"))
    ok_async = got_async == "booked B1 #1" and bookings == ["B1", "B1"] and [(r["status"], r.get("fault"), r["result"]) for r in records(writer)] == [("returned", None, "booked B1 #1"), ("returned", "duplicate-delivery", "booked B1 #2")]

    # The duplicate raising: seen first still returns the first result; seen second raises it, and
    # then the last result a reply can quote is still the one before (the agent was given none).
    def second_raises(seen):
        writer = SlowWriter(piece=4096)
        ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "refund", "kind": "duplicate-delivery", "seen": seen})
        ledger.wrap(lambda: "prior", "lookup")()
        n = []

        def refund():
            n.append(1)
            if len(n) == 2:
                raise ValueError("already refunded")
            return "r1"
        try:
            outcome = ledger.wrap(refund, "refund")()
        except ValueError as error:
            outcome = f"raised {error}"
        return outcome, [(r["status"], r.get("fault")) for r in records(writer)][1:], ledger.unfinished(), ledger.last_result
    raising = {seen: second_raises(seen) for seen in ("first", "second")}
    ok_raising = raising == {"first": ("r1", [("returned", None), ("exception", "duplicate-delivery")], 0, "r1"), "second": ("raised already refunded", [("returned", None), ("exception", "duplicate-delivery")], 0, "prior")}

    # A first delivery that raises: no duplicate, one plain record.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "refund", "kind": "duplicate-delivery"})
    runs = []

    def declined():
        runs.append(1)
        raise ValueError("card declined")
    try:
        ledger.wrap(declined, "refund")()
    except ValueError:
        pass
    ok_declined = len(runs) == 1 and [(r["status"], r.get("fault")) for r in records(writer)] == [("exception", None)]

    # Another tool's call that ends while the duplicate runs lands before both records, never between them.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "refund", "kind": "duplicate-delivery"})
    inside, release, n = threading.Event(), threading.Event(), []

    def slow_refund():
        n.append(1)
        if len(n) == 2:
            inside.set()
            release.wait(5)
        return f"r{len(n)}"
    refund, fast = ledger.wrap(slow_refund, "refund"), ledger.wrap(lambda: "fast", "fast")
    a = threading.Thread(target=refund)
    a.start()
    inside.wait(5)
    fast()
    release.set()
    a.join()
    order = [(r["tool"], r.get("fault")) for r in records(writer)]
    ok_together = order == [("fast", None), ("refund", None), ("refund", "duplicate-delivery")] and ledger.unfinished() == 0
    return ok_seen and ok_async and ok_raising and ok_declined and ok_together, {"seen": out, "async": got_async, "raising": raising, "declined": ok_declined, "order": order}


def fault_edges():
    # A duplicate cancelled or interrupted is recorded as cancelled and goes on, and the agent was
    # given no result (the last one stays the one before). Async tools: a reset commits and raises a
    # connection reset; a first call that raises is one plain record, with no duplicate.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "refund", "kind": "duplicate-delivery"})
    ledger.wrap(lambda: "prior", "lookup")()
    n = []

    def refund():
        n.append(1)
        if len(n) == 2:
            raise KeyboardInterrupt
        return "r1"
    try:
        ledger.wrap(refund, "refund")()
        interrupted = False
    except KeyboardInterrupt:
        interrupted = True
    cancel = [(r["status"], r.get("fault"), r.get("seen")) for r in records(writer)][1:]
    ok_cancel = interrupted and cancel == [("returned", None, None), ("cancelled", "duplicate-delivery", "first")] and ledger.last_result == "prior" and ledger.unfinished() == 0

    effects = []

    async def booking(code):
        await asyncio.sleep(0)
        effects.append(code)
        return f"booked {code}"

    async def declined(code):
        await asyncio.sleep(0)
        effects.append(f"declined {code}")
        raise ValueError("card declined")
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), {"tool": "booking", "kind": "reset-after-commit", "message": "connection reset by peer"})

    async def reset_run():
        try:
            await ledger.wrap(booking, "booking")("B1")
            return False
        except ConnectionResetError:
            return True
    reset = asyncio.run(reset_run())
    async_reset = [(r["status"], r.get("fault"), r.get("result")) for r in records(writer)]
    writer = SlowWriter(piece=4096)
    ledger2 = shim.Ledger(shim.Channel(out=writer), {"tool": "booking", "kind": "duplicate-delivery"})

    async def raise_run():
        try:
            await ledger2.wrap(declined, "booking")("B2")
        except ValueError:
            return True
        return False
    raised = asyncio.run(raise_run())
    async_raised = [(r["status"], r.get("fault")) for r in records(writer)]
    ok_async = reset and async_reset == [("returned", "reset-after-commit", "booked B1")] and raised and async_raised == [("exception", None)] and effects == ["B1", "declined B2"] and ledger.last_result is None
    return ok_cancel and ok_async, {"cancel": cancel, "last": ledger.last_result, "asyncReset": async_reset, "asyncRaised": async_raised, "effects": effects}


def fault_kinds_once():
    # Two concurrent first calls under a reset or a duplicate: the fault applies to one of them only.
    got = {}
    for kind in ("reset-after-commit", "duplicate-delivery"):
        writer = SlowWriter(piece=4096)
        plan = SlowFault(tool="refund", kind=kind, **({"message": "reset"} if kind == "reset-after-commit" else {}))
        ledger = shim.Ledger(shim.Channel(out=writer), plan)
        refund = ledger.wrap(lambda: "refunded", "refund")

        def go():
            try:
                refund()
            except ConnectionResetError:
                pass
        threads = [threading.Thread(target=go) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        got[kind] = sorted(str(r.get("fault")) for r in records(writer))
    ok = got == {"reset-after-commit": ["None", "reset-after-commit"], "duplicate-delivery": ["None", "None", "duplicate-delivery"]}
    return ok, got


@dataclasses.dataclass
class Box:
    inner: object = None
    items: list = dataclasses.field(default_factory=list)


def read_path():
    # Through None reads None; a missing key or attribute is an error, never None.
    roots = {"app": lambda: {"spec": Box(inner=None), "table": {"a": 1}}}
    through = shim.read_path(roots, "app.spec.inner.pizzas")
    errors = []
    for path in ["app.spec.missing", "app.table.b", "nope.x"]:
        try:
            shim.read_path(roots, path)
            errors.append(None)
        except shim.StateReadError as error:
            errors.append(str(error))
    return through is None and all(errors), {"through": through, "errors": errors}


class FieldInfo:
    def __init__(self, exclude=None):
        self.exclude = exclude


# Stand-in for pydantic's BaseModel (pydantic is not installed for these checks), laid out as pydantic
# v2 lays out a model: declared fields in __pydantic_fields__, values in the instance __dict__.
BaseModel = type("BaseModel", (), {"__module__": "pydantic.main", "__slots__": ("__dict__", "__pydantic_fields_set__", "__pydantic_extra__", "__pydantic_private__"),
                                   "model_dump": lambda self, mode="python": dict(self.__dict__)})


def model(fields, private=None, extra=None, dump=None, **values):
    """A pydantic-shaped model whose own model_dump returns `dump` (what the app chooses to report)."""
    cls = type("Booking", (BaseModel,), {"__pydantic_fields__": fields, "model_dump": lambda self, mode="python": dump})
    obj = cls()
    obj.__dict__.update(values)
    obj.__pydantic_private__, obj.__pydantic_extra__, obj.__pydantic_fields_set__ = private, extra, set(values)
    return obj


class Duck:
    """Not a pydantic model, though it has a model_dump."""

    def model_dump(self, mode="python"):
        return {"seat": "14C"}


@dataclasses.dataclass
class DumpingBox:
    seat: str = "14C"

    def model_dump(self, mode="python"):
        return {}


@dataclasses.dataclass
class SlotBase:
    seat: str = "14C"


class Slotted(SlotBase):
    __slots__ = ("hidden",)


class Ctx(dict):
    pass


class Legs(list):
    pass


class SlottedLegs(list):
    __slots__ = ("note",)


@dataclasses.dataclass
class DictDC(dict):
    seat: str = "14C"


def refused(value):
    try:
        shim.plain_data(value)
        return None
    except shim.StateReadError as error:
        return str(error)


def models():
    # A model is read by its declared fields, never by its own model_dump: a field the app's view
    # leaves out still shows. Private attributes, excluded fields, attributes outside the fields, a
    # model_dump on something that is not pydantic, and undeclared slots are refused, never dropped.
    two = {"seat": FieldInfo(), "refund_issued": FieldInfo()}
    before = shim.plain_data(model(two, dump={"seat": "14C"}, seat="14C", refund_issued=False))
    after = shim.plain_data(model(two, dump={"seat": "12C"}, seat="12C", refund_issued=True))
    extra = shim.plain_data(model({"seat": FieldInfo()}, extra={"note": "window"}, dump={}, seat="14C"))
    box = DumpingBox()
    boxed = shim.plain_data(box)
    box.refund_issued = True
    slotted = Slotted()
    slotted.hidden = "x"
    reasons = {
        "excluded": refused(model({"seat": FieldInfo(), "refund_issued": FieldInfo(exclude=True)}, dump={"seat": "14C"}, seat="14C", refund_issued=False)),
        "private": refused(model({"seat": FieldInfo()}, private={"_token": "t"}, dump={"seat": "14C"}, seat="14C")),
        "undeclared": refused(model({"seat": FieldInfo()}, dump={"seat": "14C"}, seat="14C", refund_issued=True)),
        "missing": refused(model(two, dump={"seat": "14C"}, seat="14C")),
        "duck": refused(Duck()),
        "dataclass-extra": refused(box),
        "slot": refused(slotted),
    }
    want = {"excluded": "pydantic-excluded-field", "private": "pydantic-private", "undeclared": "pydantic-attributes", "missing": "pydantic-attributes",
            "duck": "model-dump-not-pydantic", "dataclass-extra": "dataclass-extra-attribute", "slot": "undeclared-slot"}
    ok = (before == {"seat": "14C", "refund_issued": False} and after == {"seat": "12C", "refund_issued": True} and extra == {"seat": "14C", "note": "window"}
          and boxed == {"seat": "14C"} and reasons == want)
    return ok, {"before": before, "after": after, "extra": extra, "boxed": boxed, "refused": reasons}


def containers():
    # A list, tuple or dict subclass is read as its items only when it holds nothing beside them: an
    # attribute, a dataclass field or a slot on it is refused, never dropped, in a whole read and in a
    # key subset. OrderedDict, defaultdict, namedtuple and a subclass holding only items still read.
    point = collections.namedtuple("Point", "x y")
    kept = shim.plain_data({"od": collections.OrderedDict(seat="14C"), "dd": collections.defaultdict(list, legs=[1]), "nt": point(1, 2), "ctx": Ctx(seat="14C")})
    subset = shim.select_entries(Ctx(A={"n": 1}, B={"n": 2}), {"shape": "map", "key": "id", "keys": ["A"]})
    ctx = Ctx(seat="12C")
    ctx.refund_issued = True
    legs = Legs([{"id": 1}])
    legs.refund_issued = True
    slotted = SlottedLegs(["14C"])
    slotted.note = "x"

    def subset_refused(value, select):
        try:
            shim.select_entries(value, select)
            return None
        except shim.StateReadError as error:
            return str(error)
    reasons = {"dict": refused(ctx), "list": refused(legs), "dataclass": refused(DictDC()), "slot": refused(slotted), "nested": refused({"ctx": ctx}),
               "subset-map": subset_refused(ctx, {"shape": "map", "key": "id", "keys": ["seat"]}), "subset-rows": subset_refused(legs, {"shape": "rows", "key": "id", "keys": [1]})}
    want = {"dict": "container-attributes", "list": "container-attributes", "dataclass": "container-attributes", "slot": "undeclared-slot", "nested": "container-attributes",
            "subset-map": "container-attributes", "subset-rows": "container-attributes"}
    ok = (kept == {"od": {"seat": "14C"}, "dd": {"legs": [1]}, "nt": [1, 2], "ctx": {"seat": "14C"}} and subset["entries"] == {"A": {"n": 1}} and subset["remainder"]["rows"] == 1
          and reasons == want)
    return ok, {"kept": kept, "subset": subset["entries"], "refused": reasons}


def cancelled():
    # A call cancelled or interrupted after its side effect still leaves one record ('cancelled'), and
    # the cancellation goes on to the caller.
    writer = SlowWriter(piece=4096)
    ledger = shim.Ledger(shim.Channel(out=writer), None)
    effects = []

    async def booking():
        effects.append("async")
        await asyncio.sleep(5)

    def interrupted():
        effects.append("sync")
        raise KeyboardInterrupt

    slow = ledger.wrap(booking, "booking")
    stop = ledger.wrap(interrupted, "interrupted")

    async def go():
        try:
            await asyncio.wait_for(slow(), 0.05)
        except asyncio.TimeoutError:
            return "timed out"
    outcome = asyncio.run(go())
    try:
        stop()
        passed = False
    except KeyboardInterrupt:
        passed = True
    got = [(r["tool"], r["status"], r["exception"].split(":")[0]) for r in records(writer)]
    ok = got == [("booking", "cancelled", "CancelledError"), ("interrupted", "cancelled", "KeyboardInterrupt")] and passed and outcome == "timed out" and ledger.unfinished() == 0
    return ok, {"records": got, "letThrough": passed, "outcome": outcome, "unfinished": ledger.unfinished(), "effects": effects}


def plain_data():
    # Allowed: plain values, tuples, dataclasses, model_dump. Forbidden: anything a JSON reader would
    # turn into something else (a set, an object, a non-string key, NaN, an integer past 2**53).
    kept = shim.plain_data({"t": (1, "a", None, True), "box": Box(inner=2.5), "big": 2 ** 53 - 1})
    refused = []
    extra = Box(inner=1)
    extra.note = "set after construction"
    for bad in [{1, 2}, object(), {1: "a"}, float("nan"), 2 ** 53, [{"deep": {"set": {1}}}], extra]:
        try:
            shim.plain_data(bad)
            refused.append(False)
        except shim.StateReadError:
            refused.append(True)
    want = {"t": [1, "a", None, True], "box": {"inner": 2.5, "items": []}, "big": 2 ** 53 - 1}
    return kept == want and all(refused), {"kept": kept, "refused": refused}


def select_entries():
    # Only the declared keys travel; every other entry is in the remainder digest, in key order.
    table = {f"K{n}": {"n": n} for n in range(50)}
    select = {"shape": "map", "key": "id", "keys": ["K1", "K7", "MISSING"]}
    base = shim.select_entries(table, select)
    reordered = shim.select_entries(dict(reversed(list(table.items()))), select)
    inside = shim.select_entries({**table, "K1": {"n": -1}}, select)
    outside = shim.select_entries({**table, "K20": {"n": -1}}, select)
    rows = shim.select_entries([{"id": 1, "v": "a"}, {"id": "1", "v": "b"}, {"id": 2, "v": "c"}], {"shape": "rows", "key": "id", "keys": [1]})
    ok = (sorted(base["entries"]) == ["K1", "K7"] and base["remainder"]["rows"] == 48 and base["remainder"] == reordered["remainder"]
          and inside["remainder"] == base["remainder"] and outside["remainder"]["digest"] != base["remainder"]["digest"]
          and rows["entries"] == [{"id": 1, "v": "a"}] and rows["remainder"]["rows"] == 2 and shim.select_entries(None, select) is None)
    return ok, {"entries": sorted(base["entries"]), "remainder": base["remainder"], "rowsEntries": rows["entries"]}


print(json.dumps({name: check(fn) for name, fn in [("channel-lines", channel_lines), ("ledger-order", ledger_order), ("fault-once", fault_once), ("fault-reset", fault_reset), ("fault-duplicate", fault_duplicate), ("fault-kinds-once", fault_kinds_once), ("fault-edges", fault_edges), ("unfinished", unfinished), ("cancelled", cancelled), ("models", models), ("containers", containers),
                                                   ("read-path", read_path), ("plain-data", plain_data), ("select-entries", select_entries)]}))
