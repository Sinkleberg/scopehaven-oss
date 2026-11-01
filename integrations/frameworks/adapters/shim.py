"""ScopeHaven turn-runner shim for Python adapters (scopehaven-turn-runner/1).

The harness writes one JSON object per line to stdin; the shim answers on file
descriptor 3, so the template's own prints and logs stay on stdout/stderr.

Pieces every Python adapter shares:
  Channel   the two streams; writes to fd 3 are serialized, so tools that run in
            worker threads or concurrently never interleave their lines
  Ledger    presence-only tool ledger, and the fault hook at the tool boundary
            (fault.mjs) on the first call to the planned tool: a timeout raises
            before the tool body runs and leaves a 'fault-injected' record; a
            reset after commit lets the body return, marks its record, and raises
            a connection reset instead of the result; a duplicate delivery runs
            the body twice with the same arguments, writes both records together,
            and returns the first result (the duplicate's with seen 'second'). A
            first call that raises spends the fault without firing it. The
            sequence number is taken when a record is written, so overlapping
            calls still arrive 1, 2, 3 (a call that started first may end last).
            Every call that starts writes exactly one record when it ends: returned,
            exception, or cancelled (a CancelledError or KeyboardInterrupt, recorded
            and then let through); unfinished() counts calls still running, so an
            adapter can fail a turn that ends with one
  Script    the scripted stub model's steps for the current turn
  snapshot_values  the answer to a snapshot request: each operator-named path
            read below the adapter's roots (read_path), as plain data
            (plain_data), cut to its declared key subset when the request has
            one (select_entries)
No network, no model calls, standard library only.
"""
import dataclasses
import functools
import hashlib
import inspect
import json
import math
import os
import re
import sys
import threading

PROTOCOL = "scopehaven-turn-runner/1"
JSON_CAP = 60000
CONTEXT_TYPES = ("RunnableConfig", "RunContextWrapper", "ToolContext", "RunContext", "CallbackManagerForToolRun")
SKIP_KWARGS = {"config", "context", "tool_context", "callback_context", "run_manager", "callbacks"}


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def jsonable(value, depth=0):
    if depth > 6:
        return repr(value)[:400]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:4000]
    if isinstance(value, dict):
        return {str(k): jsonable(v, depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v, depth + 1) for v in list(value)[:100]]
    if hasattr(value, "model_dump"):
        try:
            return jsonable(value.model_dump(), depth + 1)
        except Exception:
            pass
    return repr(value)[:400]


def capped(value):
    """A JSON-safe value under the contract's size cap, or a digest of it."""
    out = jsonable(value)
    text = json.dumps(out, default=str)
    if len(text) <= JSON_CAP:
        return out
    return {"truncated": True, "sha256": sha256_text(text), "chars": len(text)}


def _exception_text(error):
    try:
        text = f"{type(error).__name__}: {error}"
    except Exception:
        text = type(error).__name__
    return text[:4000]


def safely_capped(value):
    """capped(), or a marker naming the failure: a call's record is never lost to its arguments or result."""
    try:
        return capped(value)
    except Exception as error:
        return {"unrecordable": type(error).__name__}


class Channel:
    def __init__(self, out=None):
        self.out = out if out is not None else os.fdopen(3, "w", buffering=1, encoding="utf-8")
        self.lock = threading.Lock()

    def send(self, message):
        line = json.dumps(message, default=str) + "\n"
        # One whole line per write: tools may run in worker threads (llama_index) or concurrently.
        with self.lock:
            self.out.write(line)
            self.out.flush()

    def messages(self):
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield json.loads(line)


class FaultRaised(Exception):
    pass


class Ledger:
    """Wraps tool functions: one record per call (name, arguments, return or exception)."""

    def __init__(self, channel, fault):
        self.channel = channel
        self.fault = fault
        self.fault_used = False
        self.seq = 0
        self.last_result = None
        self.lock = threading.Lock()
        self.running = 0

    def _write(self, record):
        # Caller holds self.lock. The number is taken as the record is written, so arrival order is seq order.
        self.seq += 1
        self.running -= 1
        self.channel.send({"type": "tool", "record": {"seq": self.seq, **record}})

    def unfinished(self):
        """Tool calls started and not yet recorded. An adapter reports a turn that ends with any as a
        failure: a call still running may write after the snapshot, and its record would be missing."""
        with self.lock:
            return self.running

    def _record(self, record):
        with self.lock:
            self._write(record)

    def _begin(self, name, args, kwargs):
        pos = ["<context>" if type(a).__name__ in CONTEXT_TYPES else a for a in args]
        kw = {k: ("<omitted>" if k in SKIP_KWARGS else v) for k, v in kwargs.items()}
        rec = {"tool": name, "args": safely_capped({"args": pos, "kwargs": kw})}
        with self.lock:
            self.running += 1
        return rec

    def _maybe_fault(self, name, rec):
        # Decided under one lock, so two concurrent first calls fault once. A timeout is recorded in
        # the same step, so its record is the tool's first whichever call's body ends first; a reset
        # or a duplicate is applied once the body has run, so its kind is returned.
        f = self.fault
        with self.lock:
            if not (f and not self.fault_used and name == f["tool"]):
                return
            self.fault_used = True
            if f["kind"] != "timeout":
                return f["kind"]
            rec.update(status="fault-injected", exception=f"TimeoutError: {f['message']}")
            self._write(rec)
        raise TimeoutError(f["message"])

    def _returned(self, rec, result):
        rec.update(status="returned", result=safely_capped(result))
        with self.lock:
            self.last_result = result
            self._write(rec)

    def _after_body(self, kind, rec, result):
        """A body that returned: its result, or under a reset its record marked and a connection reset
        in place of the result (the agent never sees it, so it is not the last result either)."""
        if kind != "reset-after-commit":
            self._returned(rec, result)
            return result
        rec.update(status="returned", result=safely_capped(result), fault=kind)
        self._record(rec)
        raise ConnectionResetError(self.fault["message"])

    def _redeliver(self):
        # The duplicate delivery is a call of its own until its record is written.
        with self.lock:
            self.running += 1

    def _delivered_twice(self, rec, result, second, error):
        """Both deliveries' records in one locked step, so nothing lands between them. The agent gets
        the first result, or with seen 'second' the duplicate's (or its exception); a cancelled or
        interrupted duplicate always goes on."""
        seen = self.fault.get("seen", "first")
        dup = {**rec, "fault": "duplicate-delivery", "seen": seen}
        if error is None:
            dup.update(status="returned", result=safely_capped(second))
        else:
            dup.update(status="exception" if isinstance(error, Exception) else "cancelled", exception=_exception_text(error))
        rec.update(status="returned", result=safely_capped(result))
        shown = second if seen == "second" else result
        # What the agent is given: the result `seen` names, unless that delivery raised, or the
        # duplicate was cancelled or interrupted (which always goes on). Only a given result is the last.
        delivered = error is None or (isinstance(error, Exception) and seen == "first")
        with self.lock:
            if delivered:
                self.last_result = shown
            self._write(rec)
            self._write(dup)
        if not delivered:
            raise error
        return shown

    def _raised(self, rec, error, status="exception"):
        rec.update(status=status, exception=_exception_text(error))
        self._record(rec)

    def wrap(self, fn, name=None):
        name = name or fn.__name__
        ledger = self
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*args, **kwargs):
                rec = ledger._begin(name, args, kwargs)
                kind = ledger._maybe_fault(name, rec)
                try:
                    result = await fn(*args, **kwargs)
                except Exception as error:
                    ledger._raised(rec, error)
                    raise
                except BaseException as error:
                    # Cancelled or interrupted (CancelledError, KeyboardInterrupt): recorded, then let through.
                    ledger._raised(rec, error, "cancelled")
                    raise
                if kind != "duplicate-delivery":
                    return ledger._after_body(kind, rec, result)
                ledger._redeliver()
                try:
                    second, caught = await fn(*args, **kwargs), None
                except BaseException as error:
                    second, caught = None, error
                return ledger._delivered_twice(rec, result, second, caught)
            return awrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            rec = ledger._begin(name, args, kwargs)
            kind = ledger._maybe_fault(name, rec)
            try:
                result = fn(*args, **kwargs)
            except Exception as error:
                ledger._raised(rec, error)
                raise
            except BaseException as error:
                ledger._raised(rec, error, "cancelled")
                raise
            if kind != "duplicate-delivery":
                return ledger._after_body(kind, rec, result)
            ledger._redeliver()
            try:
                second, caught = fn(*args, **kwargs), None
            except BaseException as error:
                second, caught = None, error
            return ledger._delivered_twice(rec, result, second, caught)
        return wrapper


class Script:
    """The scripted stub model's steps for one turn, consumed in order."""

    def __init__(self, ledger):
        self.ledger = ledger
        self.steps = []
        self.consumed = 0
        self.exhausted = False
        self.calls = 0

    def start_turn(self, steps):
        self.steps = list(steps)
        self.consumed = 0
        self.exhausted = False

    def next_step(self):
        self.calls += 1
        if self.consumed >= len(self.steps):
            self.exhausted = True
            return None
        step = self.steps[self.consumed]
        self.consumed += 1
        return step

    def render(self, text):
        last = self.ledger.last_result

        def field(match):
            if isinstance(last, dict) and match.group(1) in last:
                return str(last[match.group(1)])
            return match.group(0)
        return re.sub(r"\{\{last\.([A-Za-z_][A-Za-z0-9_]*)\}\}", field, text)

    def status(self):
        return {"consumed": self.consumed, "exhausted": self.exhausted}


def sub_once(source, old, new, label, applied):
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"declared substitution {label} matched {count} times")
    out = source.replace(old, new)
    applied.append({"name": label, "beforeSha256": sha256_text(source), "afterSha256": sha256_text(out)})
    return out


# ---------------------------------------------------------------- object-path state
SAFE_INTEGER = 2 ** 53 - 1
STATE_DEPTH = 32


class StateReadError(Exception):
    pass


# Slots pydantic's own BaseModel declares; any other slot holds state a read by fields would miss.
_PYDANTIC_SLOTS = {"__dict__", "__weakref__", "__pydantic_fields_set__", "__pydantic_extra__", "__pydantic_private__"}


def _undeclared_slots(value, declared):
    """Slot names in the class hierarchy that are not declared fields."""
    names = set()
    for cls in type(value).__mro__:
        slots = cls.__dict__.get("__slots__", ())
        names.update([slots] if isinstance(slots, str) else slots)
    return [n for n in names if n not in declared and n not in _PYDANTIC_SLOTS]


def _pydantic_model(value):
    """True when the value's class derives from pydantic's own BaseModel (pydantic.main.BaseModel)."""
    return any(cls.__name__ == "BaseModel" and cls.__module__ == "pydantic.main" for cls in type(value).__mro__)


def _items_only(value):
    """A list, tuple or dict subclass is read as its items, so one holding anything beside them (an
    attribute, a dataclass field, a slot) is refused, never dropped. OrderedDict, defaultdict and
    namedtuple hold nothing else and still read."""
    if not isinstance(value, (list, tuple, dict)) or type(value) in (list, tuple, dict):
        return
    if getattr(value, "__dict__", None):
        raise StateReadError("container-attributes")
    if _undeclared_slots(value, ()):
        raise StateReadError("undeclared-slot")


def plain_data(value, depth=0):
    """The value as plain JSON data, or StateReadError: what an object-path snapshot may carry.
    As adapters/plain-data.mjs, nothing is stringified or dropped: anything that cannot be read
    whole is refused. A dataclass is read as its fields, and a pydantic model as its declared
    fields (plus its extras), each as the object holds it; the app's own model_dump is never
    called, since it can leave fields out or rewrite them. Refused: a set, any other object, a
    non-string key, a non-finite float, an integer past 2**53 (JSON readers would round it), an
    attribute or slot outside the declared fields, a list, tuple or dict subclass holding anything
    beside its items, a model with private attributes or an excluded field, and anything with a
    model_dump that is not a pydantic model. A str, int or float subclass is read as its value."""
    if depth > STATE_DEPTH:
        raise StateReadError("depth")
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise StateReadError("unsafe-integer")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StateReadError("number")
        return value
    _items_only(value)
    if isinstance(value, (list, tuple)):
        return [plain_data(v, depth + 1) for v in value]
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise StateReadError("key")
        return {k: plain_data(v, depth + 1) for k, v in value.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        names = [f.name for f in dataclasses.fields(value)]
        # An attribute set on the instance outside its fields would be dropped: refused instead.
        if any(k not in names for k in getattr(value, "__dict__", {})):
            raise StateReadError("dataclass-extra-attribute")
        if _undeclared_slots(value, names):
            raise StateReadError("undeclared-slot")
        return {n: plain_data(getattr(value, n), depth + 1) for n in names}
    if callable(getattr(value, "model_dump", None)) and not isinstance(value, type):
        if not _pydantic_model(value):
            raise StateReadError("model-dump-not-pydantic")
        fields = getattr(type(value), "__pydantic_fields__", None)
        if not isinstance(fields, dict):
            fields = getattr(type(value), "model_fields", None)  # pydantic 2 before 2.10
        if not isinstance(fields, dict) or not all(isinstance(k, str) for k in fields):
            raise StateReadError("pydantic-fields")
        if getattr(value, "__pydantic_private__", None):
            raise StateReadError("pydantic-private")
        if any(getattr(f, "exclude", None) for f in fields.values()):
            raise StateReadError("pydantic-excluded-field")
        # The held values: every declared field, and nothing else, in the instance __dict__.
        held = getattr(value, "__dict__", None)
        if not isinstance(held, dict) or set(held) != set(fields):
            raise StateReadError("pydantic-attributes")
        if _undeclared_slots(value, fields):
            raise StateReadError("undeclared-slot")
        out = {n: plain_data(held[n], depth + 1) for n in fields}
        extra = getattr(value, "__pydantic_extra__", None)
        if extra:
            if not isinstance(extra, dict) or not all(isinstance(k, str) and k not in out for k in extra):
                raise StateReadError("pydantic-extra")
            out.update({k: plain_data(v, depth + 1) for k, v in extra.items()})
        return out
    raise StateReadError(f"unsupported:{type(value).__name__}")


_MISSING = object()


def read_path(roots, path):
    """The object at an operator-named dotted path: `roots` maps the first step to a function that
    returns the template's own object; each later step is one dict key or, for anything that is not
    a dict, one attribute. A step through None reads None (an artifact not created yet; the
    projection's nullAs decides what that means). A missing key or attribute is an error, never None."""
    head, *rest = path.split(".")
    if head not in roots:
        raise StateReadError(f"unknown-root:{head}")
    value = roots[head]()
    for step in rest:
        if value is None:
            return None
        value = value.get(step, _MISSING) if isinstance(value, dict) else getattr(value, step, _MISSING)
        if value is _MISSING:
            raise StateReadError(f"missing:{step}")
    return value


def _key_text(key):
    return json.dumps(key, ensure_ascii=False)


def select_entries(value, select):
    """A declared key subset of a map (shape 'map') or of a keyed list (shape 'rows'), as
    {"entries": ..., "remainder": {"rows": n, "digest": "#sha256"}}: the entries for the declared
    keys only, and one digest over every other entry in key order, so a table too large for one
    state message is still watched whole. None stays None."""
    if value is None:
        return None
    _items_only(value)
    wanted ={_key_text(k) for k in select["keys"]}
    others = []
    if select["shape"] == "map":
        if not isinstance(value, dict):
            raise StateReadError("map-not-dict")
        entries = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise StateReadError("key")
            if _key_text(k) in wanted:
                entries[k] = plain_data(v)
            else:
                others.append((_key_text(k), [k, plain_data(v)]))
    elif select["shape"] == "rows":
        if not isinstance(value, (list, tuple)):
            raise StateReadError("rows-not-list")
        entries = []
        for record in value:
            row = plain_data(record)
            if not isinstance(row, dict) or select["key"] not in row:
                raise StateReadError("key-missing")
            if _key_text(row[select["key"]]) in wanted:
                entries.append(row)
            else:
                others.append((_key_text(row[select["key"]]), row))
    else:
        raise StateReadError("shape")
    # Digested as this adapter's JSON text (Python's: 1.0 and 1 differ), compared only with itself.
    digest = hashlib.sha256()
    for _, entry in sorted(others, key=lambda pair: pair[0]):
        digest.update(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8", "surrogatepass"))
        digest.update(b"\n")
    return {"entries": entries, "remainder": {"rows": len(others), "digest": "#" + digest.hexdigest()}}


def snapshot_values(roots, paths):
    """The values for one snapshot request: {path: value}. Only 'object-path' reads; an adapter
    with an application reporting hook answers 'app-report' paths itself."""
    values = {}
    for p in paths:
        if p.get("source") != "object-path":
            raise StateReadError("no-app-report-hook")
        held = read_path(roots, p["path"])
        values[p["path"]] = select_entries(held, p["select"]) if "select" in p else plain_data(held)
    return values
