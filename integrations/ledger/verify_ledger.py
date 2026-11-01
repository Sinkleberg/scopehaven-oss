#!/usr/bin/env python3
"""Independent verifier for a Scopehaven evidence ledger (scopehaven-ledger/1).

Standard library only (Python 3.8+). It shares no code with the Node writer or verifier.
Signatures and envelopes are checked with ../attest/verify_envelope.py, the independent
attest verifier. Hash chain, Merkle tree heads and RFC 9162 proofs are written out here.

    python3 verify_ledger.py log --key LEDGER_PUB.pem [--evidence-key PUB.pem] --ledger DIR
    python3 verify_ledger.py inclusion --key LEDGER_PUB.pem --entry ENTRY.json --proof PROOF.json --checkpoint CHECKPOINT.json
    python3 verify_ledger.py consistency --key LEDGER_PUB.pem --older A.json --newer B.json --proof PROOF.json

A verified ledger shows that the log operator's key signed these entries in this order, and
that each entry's envelope was signed by the evidence key. It does not show the results are
correct. A checkpoint is not externally witnessed: the operator could show different histories
to different readers unless checkpoints are compared.

Exit codes: 0 verified, 1 rejected, 2 usage or file error, 3 self-check failed.
"""
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attest"))
import verify_envelope as attest  # noqa: E402  (the independent attest verifier)

Rejected = attest.Rejected
LEDGER_VERSION = "scopehaven-ledger/1"
CHECKPOINT_VERSION = "scopehaven-ledger-checkpoint/1"
CHECKPOINT_TYPE = "application/vnd.scopehaven.ledger-checkpoint+json"
INCLUSION_VERSION = "scopehaven-ledger-inclusion/1"
CONSISTENCY_VERSION = "scopehaven-ledger-consistency/1"
CHECKPOINT_MEANING = ("Signed by the log operator's own key over this log's first treeSize entries. Not externally witnessed: "
                      "an operator could show different histories to different readers, so compare checkpoints with others "
                      "who hold them, or keep your own.")
STATUSES = ("pass", "fail", "inconclusive", "error", "not_applicable")
CUSTODY = ("subject-writable", "observer-held", "independent")  # EVID-SUBJECT's vocabulary, as a schema enum
RECORDED = ("verdicts", "verdictDigest", "anchors")
LIMITS = {"depth": 256, "entries": 100000, "lineBytes": 262144, "checkpoints": 100000, "runsPerEntry": 64, "checksPerRun": 1000, "proofLength": 64, "anchorsPerRun": 64,
          "cosignatures": 100000, "witnesses": 64}
HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
ISO = re.compile(r"2\d{3}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z", re.ASCII)
SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)  # observer source names: one ASCII rule
LOG_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.ASCII)


def _sha(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def leaf_hash(data):
    return _sha(b"\x00", data)


def _node(left, right):
    return _sha(b"\x01", left, right)


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_heads_at(leaves, sizes):
    """Tree heads of every requested prefix size in one pass (a right fold of the frontier of
    perfect subtrees is the RFC 9162 head), so verifying is O(n log n)."""
    wanted, heads, stack = set(sizes), {}, []
    for i, leaf in enumerate(leaves):
        size, value = 1, leaf
        while stack and stack[-1][0] == size:
            s, h = stack.pop()
            size, value = s * 2, _node(h, value)
        stack.append((size, value))
        if i + 1 in wanted:
            r = stack[-1][1]
            for j in range(len(stack) - 2, -1, -1):
                r = _node(stack[j][1], r)
            heads[i + 1] = r
    return heads


def tree_head(leaves):
    """RFC 9162 section 2.1.1 Merkle tree head."""
    if not leaves:
        return _sha()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(tree_head(leaves[:k]), tree_head(leaves[k:]))


def _iso_time(value):
    if not isinstance(value, str) or not ISO.match(value):
        return None
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    text = "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (moment.year, moment.month, moment.day, moment.hour, moment.minute,
                                                   moment.second, moment.microsecond // 1000)
    return moment if text == value else None


def _at(value):
    """A timestamp already checked by _iso_time, as a datetime for ordering."""
    return _iso_time(value) or datetime.min.replace(tzinfo=timezone.utc)


def _exact(value, keys):
    return isinstance(value, dict) and len(value) == len(keys) and all(k in value for k in keys)


def _int(value):
    """An integer JavaScript holds exactly (Number.isSafeInteger), never a bool."""
    return isinstance(value, int) and not isinstance(value, bool) and -(2 ** 53 - 1) <= value <= 2 ** 53 - 1


def _trimmed(text):
    """Surrounding whitespace both verifiers ignore: space, tab, CR and LF only."""
    return text.strip(" \t\r\n")


def too_deep(text, limit=None):
    """JSON nesting depth of a text, counted outside strings, as verify.mjs counts it. Both verifiers
    refuse anything deeper than LIMITS["depth"] before parsing, so neither parser's limits decide."""
    limit = LIMITS["depth"] if limit is None else limit
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def _js_int_text(digits):
    """JSON.parse reads every number as a double. An integer JavaScript holds exactly (up to 2^53 - 1
    in magnitude) stays an int, as Number.isSafeInteger sees it; anything larger is the double
    JavaScript would hold. Parsing through float means Python's integer-digit limit never applies."""
    value = float(digits)
    return int(value) if abs(value) <= 2 ** 53 - 1 else value


def json_js(text):
    """Parse JSON text as JavaScript's JSON.parse does (numbers as doubles, no NaN or Infinity).
    Raises attest.NotJSON for text it would refuse."""
    try:
        return json.loads(text, parse_constant=attest._no_constants, parse_int=_js_int_text)
    except json.JSONDecodeError as error:
        raise attest.NotJSON(str(error))


def _canonical(text, shape_reason, canonical_reason):
    if too_deep(text):
        raise Rejected(shape_reason, "nested too deep")
    try:
        value = json_js(text)
    except (ValueError, RecursionError):
        raise Rejected(shape_reason, "not JSON")
    try:
        same = attest._js_json(value) == text
    except RecursionError:
        raise Rejected(shape_reason, "nested too deep")
    if not same:
        raise Rejected(canonical_reason)
    return value


def _lines(data, limit, reason):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected(reason, "not UTF-8")
    if not text:
        return []
    if not text.endswith("\n"):
        raise Rejected(reason, "the last line is incomplete")
    items = text[:-1].split("\n")
    if len(items) > limit or any(not line or len(line.encode("utf-8")) > LIMITS["lineBytes"] for line in items):
        raise Rejected(reason, "empty or oversized line, or too many lines")
    return items


def _b64(text):
    try:
        return attest._strict_base64(text, "")
    except Rejected:
        return None


def read_metadata(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected("ledger-shape")
    meta = _canonical(text[:-1] if text.endswith("\n") else text, "ledger-shape", "ledger-shape")
    if (not _exact(meta, ("ledger", "log", "createdAt")) or meta["ledger"] != LEDGER_VERSION or not isinstance(meta["log"], str)
            or not LOG_ID.match(meta["log"]) or _iso_time(meta["createdAt"]) is None):
        raise Rejected("ledger-shape")
    return meta


def _id_key(run):
    """A run id as JavaScript's Set compares it (new Set(runs.map(r => r?.id))): a list or object id
    is distinct from every other, a missing id is undefined, and true is not 1."""
    if not isinstance(run, dict) or "id" not in run:
        return ("undefined",)
    value = run["id"]
    if isinstance(value, (list, dict)):
        return ("object", id(value))
    if isinstance(value, bool) or value is None:
        return ("constant", value)
    if isinstance(value, (int, float)):
        return ("number", float(value))
    return ("string", value)


def _entry_shape(entry):
    if not _exact(entry, ("index", "prev", "recordedAt", "envelope", "runs")):
        raise Rejected("entry-shape")
    where = "entry %s" % entry["index"]
    if (not _int(entry["index"]) or entry["index"] < 0 or not (entry["prev"] is None or (isinstance(entry["prev"], str) and HEX64.match(entry["prev"])))
            or _iso_time(entry["recordedAt"]) is None):
        raise Rejected("entry-shape", where)
    env = entry["envelope"]
    if not _exact(env, ("sha256", "keyid")) or not all(isinstance(v, str) and HEX64.match(v) for v in (env["sha256"], env["keyid"])):
        raise Rejected("entry-shape", where + " envelope")
    if not isinstance(entry["runs"], list) or len(entry["runs"]) > LIMITS["runsPerEntry"]:
        raise Rejected("entry-shape", where + " runs")
    if len(set(_id_key(run) for run in entry["runs"])) != len(entry["runs"]):
        raise Rejected("entry-shape", where + " records one run id twice")
    for run in entry["runs"]:
        if (not isinstance(run, dict) or not isinstance(run.get("subject"), str) or not isinstance(run.get("id"), str) or not run["id"]
                or not isinstance(run.get("verdicts"), list)
                or not isinstance(run.get("verdictDigest"), str) or not HEX64.match(run["verdictDigest"])):
            raise Rejected("entry-shape", where + " run")
        if any(k not in RECORDED and not attest._scalar(v) for k, v in run.items()):
            raise Rejected("entry-shape", where + " run identity")
        anchors = run.get("anchors")
        if (not isinstance(anchors, list) or len(anchors) > LIMITS["anchorsPerRun"]
                or not all(_exact(a, ("source", "custody", "count", "head")) and isinstance(a["source"], str) and SOURCE.match(a["source"]) is not None
                           and a["custody"] in CUSTODY and _int(a["count"]) and a["count"] >= 0
                           and ((a["head"] is None) if a["count"] == 0 else (isinstance(a["head"], str) and HEX64.match(a["head"]) is not None))
                           for a in anchors)
                or len(set(a["source"] for a in anchors)) != len(anchors)):
            raise Rejected("entry-shape", where + " anchors")
        verdicts = run["verdicts"]
        if (len(verdicts) > LIMITS["checksPerRun"]
                or not all(isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and v[0] and v[1] in STATUSES for v in verdicts)
                or len(set(v[0] for v in verdicts)) != len(verdicts)):
            raise Rejected("entry-shape", where + " verdicts")


def _identity(run):
    return {k: v for k, v in run.items() if k not in RECORDED}


def verdict_digest(verdicts):
    return hashlib.sha256(attest._canonical_json(verdicts)).hexdigest()


def _check_chain(entries, created_at):
    leaves = []
    for i, (line, entry) in enumerate(entries):
        _entry_shape(entry)
        if entry["index"] != i:
            raise Rejected("index-mismatch", "line %d holds entry %s" % (i + 1, entry["index"]))
        if entry["prev"] != (leaves[i - 1].hex() if i else None):
            raise Rejected("chain-broken", "entry %d does not follow entry %d" % (i, i - 1))
        before = entries[i - 1][1]["recordedAt"] if i else created_at
        if _at(entry["recordedAt"]) < _at(before):
            raise Rejected("time-regression", "entry %d is dated before %s" % (i, "entry %d" % (i - 1) if i else "the ledger"))
        for run in entry["runs"]:
            if verdict_digest(run["verdicts"]) != run["verdictDigest"]:
                raise Rejected("verdict-digest-mismatch", "entry %d" % i)
        leaves.append(leaf_hash(line.encode("utf-8")))
    return leaves


def read_checkpoint(text, public, keyid, log=None, check_signature=None, created_at=None):
    check_signature = check_signature or attest.ed25519_verify
    if too_deep(text):
        raise Rejected("checkpoint-shape", "nested too deep")
    try:
        env = json_js(text)
    except (ValueError, RecursionError):
        raise Rejected("checkpoint-shape", "not JSON")
    try:
        same = attest._js_json(env) == text
    except RecursionError:
        same = False
    if not same:
        raise Rejected("checkpoint-shape", "not canonical")
    if (not _exact(env, ("payload", "payloadType", "signatures")) or env["payloadType"] != CHECKPOINT_TYPE
            or not isinstance(env["signatures"], list) or len(env["signatures"]) != 1
            or not _exact(env["signatures"][0], ("keyid", "sig")) or not isinstance(env["signatures"][0]["keyid"], str)):
        raise Rejected("checkpoint-shape")
    payload, sig = _b64(env["payload"]), _b64(env["signatures"][0]["sig"])
    if payload is None or sig is None or len(payload) > LIMITS["lineBytes"]:
        raise Rejected("checkpoint-shape", "base64")
    if env["signatures"][0]["keyid"] != keyid:
        raise Rejected("keyid-mismatch", "checkpoint signed by a different key than the trusted ledger key")
    if len(sig) != 64 or not check_signature(public, attest.pae(CHECKPOINT_TYPE, payload), sig):
        raise Rejected("checkpoint-signature")
    try:
        body = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected("checkpoint-shape")
    point = _canonical(body, "checkpoint-shape", "checkpoint-shape")
    if (not _exact(point, ("_type", "log", "ledgerCreatedAt", "treeSize", "rootHash", "headHash", "signedAt", "witness", "meaning"))
            or point["_type"] != CHECKPOINT_VERSION or (log is not None and point["log"] != log)
            or not isinstance(point["log"], str) or not LOG_ID.match(point["log"]) or _iso_time(point["ledgerCreatedAt"]) is None
            or not _int(point["treeSize"]) or point["treeSize"] < 1 or point["treeSize"] > LIMITS["entries"]
            or not all(isinstance(v, str) and HEX64.match(v) for v in (point["rootHash"], point["headHash"]))
            or _iso_time(point["signedAt"]) is None or point["witness"] != "none" or point["meaning"] != CHECKPOINT_MEANING):
        raise Rejected("checkpoint-shape")
    if created_at is not None and point["ledgerCreatedAt"] != created_at:
        raise Rejected("ledger-mismatch", "ledger.json does not match the signed checkpoint")
    return point


def _examine(metadata, entries_data, checkpoints_data, envelopes, public, keyid, evidence_pem, check_signature, run_files=None):
    meta = read_metadata(metadata)
    entries = [(line, _canonical(line, "entry-shape", "entry-not-canonical")) for line in _lines(entries_data, LIMITS["entries"], "entry-shape")]
    leaves = _check_chain(entries, meta["createdAt"])
    seen, run_ids, verdicts_checked, run_count = set(), set(), 0, 0
    for _, entry in entries:
        if entry["envelope"]["sha256"] in seen:
            raise Rejected("envelope-duplicate", "entry %d repeats an earlier envelope" % entry["index"])
        seen.add(entry["envelope"]["sha256"])
        for run in entry["runs"]:
            if run["id"] in run_ids:
                raise Rejected("run-replayed", "entry %d records run %s again" % (entry["index"], run["id"]))
            run_ids.add(run["id"])
        data = envelopes.get(entry["envelope"]["sha256"])
        if not isinstance(data, bytes):
            raise Rejected("envelope-missing", "entry %d" % entry["index"])
        if hashlib.sha256(data).hexdigest() != entry["envelope"]["sha256"]:
            raise Rejected("envelope-mismatch", "entry %d" % entry["index"])
        try:
            read = attest.read_signed_statement(data, evidence_pem)
        except Rejected as error:
            raise Rejected("envelope-invalid", "entry %d: %s" % (entry["index"], error.reason))
        if read["keyid"] != entry["envelope"]["keyid"]:
            raise Rejected("envelope-invalid", "entry %d: keyid" % entry["index"])
        if _at(entry["recordedAt"]) < _at(read["statement"]["predicate"]["signedAt"]):
            raise Rejected("time-regression", "entry %d is dated before its evidence was signed" % entry["index"])
        if attest._canonical_json([_identity(run) for run in entry["runs"]]) != attest._canonical_json(read["statement"]["predicate"]["runs"]):
            raise Rejected("run-mismatch", "entry %d" % entry["index"])
        for run in entry["runs"]:
            run_count += 1
            subject = next((s for s in read["statement"]["subject"] if s["name"] == run["subject"]), None)
            data = (run_files or {}).get(subject["digest"]["sha256"]) if subject else None
            if data is None:
                continue
            payments = _is_payments(run)
            results = _run_results(data, payments)
            if results is None:
                raise Rejected("verdict-mismatch", "entry %d: run file unreadable or not a %s"
                               % (entry["index"], "payments run the pack's reader takes" if payments else "run export"))
            if attest._canonical_json(results) != attest._canonical_json(run["verdicts"]):
                raise Rejected("verdict-mismatch", "entry %d: recorded verdicts differ from the signed run file" % entry["index"])
            verdicts_checked += 1
    raw = _lines(checkpoints_data, LIMITS["checkpoints"], "checkpoint-shape")
    if not raw:
        raise Rejected("no-checkpoint", "no signed checkpoint covers this log")
    points = [read_checkpoint(text, public, keyid, meta["log"], check_signature, meta["createdAt"]) for text in raw]
    by_size = {}
    for p in points:
        seen_point = by_size.get(p["treeSize"])
        if seen_point and (seen_point["rootHash"] != p["rootHash"] or seen_point["headHash"] != p["headHash"]):
            raise Rejected("fork", "two signed heads at size %d" % p["treeSize"])
        by_size[p["treeSize"]] = p
    for i in range(1, len(points)):
        if points[i]["treeSize"] < points[i - 1]["treeSize"] or _at(points[i]["signedAt"]) < _at(points[i - 1]["signedAt"]):
            raise Rejected("checkpoint-regression", "checkpoint %d goes back in size or time" % (i + 1))
    heads = tree_heads_at(leaves, [p["treeSize"] for p in points])
    for point in points:
        size = point["treeSize"]
        if size > len(leaves):
            raise Rejected("checkpoint-mismatch", "a checkpoint covers %d entries; the log has %d" % (size, len(leaves)))
        if heads[size].hex() != point["rootHash"] or leaves[size - 1].hex() != point["headHash"]:
            raise Rejected("checkpoint-mismatch", "size %d" % size)
        # Entry times never decrease (checked above), so the last covered entry is the latest.
        if _at(entries[size - 1][1]["recordedAt"]) > _at(point["signedAt"]):
            raise Rejected("time-regression", "an entry is dated after the checkpoint at size %d" % size)
    return {"meta": meta, "entries": entries, "leaves": leaves, "points": points, "raw": raw, "envelopes": envelopes,
            "evidence": evidence_pem, "verdictsChecked": verdicts_checked, "runCount": run_count}


def _flip(data):
    copy = bytearray(data)
    copy[len(copy) >> 1] ^= 1
    return bytes(copy)


def _inclusion_path_for(leaves, m):
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return _inclusion_path_for(leaves[:k], m) + [tree_head(leaves[k:])]
    return _inclusion_path_for(leaves[k:], m - k) + [tree_head(leaves[:k])]


def _negative_controls(state, public, check_signature):
    entries, leaves, last = state["entries"], state["leaves"], state["points"][-1]
    env = json.loads(state["raw"][-1])
    payload, sig = base64.b64decode(env["payload"]), base64.b64decode(env["signatures"][0]["sig"])
    other = attest.ed25519_public(os.urandom(32))
    size = last["treeSize"]

    def reordered():
        try:
            _check_chain([entries[1], entries[0]] + entries[2:], state["meta"]["createdAt"])
            return True
        except Rejected:
            return False

    controls = [
        ("checkpoint-payload-tampered", lambda: check_signature(public, attest.pae(CHECKPOINT_TYPE, _flip(payload)), sig)),
        ("checkpoint-wrong-key", lambda: check_signature(other, attest.pae(CHECKPOINT_TYPE, payload), sig)),
        ("entry-rewritten", lambda: tree_head([leaf_hash(_flip(entries[0][0].encode("utf-8")))] + leaves[1:size]).hex() == last["rootHash"]),
        ("inclusion-path-tampered", lambda: size > 1 and verify_inclusion_path(
            leaves[0], 0, size, [(_flip(h) if i == 0 else h) for i, h in enumerate(_inclusion_path_for(leaves[:size], 0))], bytes.fromhex(last["rootHash"]))),
    ]
    # The envelope signature path: a stored envelope with one signature bit flipped must not read.
    stored = json.loads(state["envelopes"][entries[0][1]["envelope"]["sha256"]])
    stored["signatures"][0]["sig"] = base64.b64encode(_flip(base64.b64decode(stored["signatures"][0]["sig"]))).decode("ascii")

    def envelope_tampered():
        try:
            attest.read_signed_statement(json.dumps(stored).encode("utf-8"), state["evidence"])
            return True
        except Rejected:
            return False

    controls.append(("envelope-signature-tampered", envelope_tampered))
    if len(entries) > 1:
        controls.append(("entries-reordered", reordered))
    results = []
    for name, attempt in controls:
        try:
            accepted = attempt() is True
        except Rejected:
            accepted = False
        results.append({"id": name, "expected": "rejected", "observed": "accepted" if accepted else "rejected"})
    return results


# ---- Witness cosignatures (C2SP tlog-cosignature, cosignature/v1), as in verify.mjs ----
def cosignature_origin(log):
    return "scopehaven-ledger/" + log


def checkpoint_note(origin, tree_size, root_hash):
    return "%s\n%d\n%s\n" % (origin, tree_size, base64.b64encode(bytes.fromhex(root_hash)).decode("ascii"))


def cosigned_message(time, note):
    return ("cosignature/v1\ntime %d\n%s" % (time, note)).encode("utf-8")


# Cosigner names, as cosignerName in verify.mjs: a non-empty UTF-8 string of at most 255 bytes with no
# Unicode spaces (the White_Space property), no "+" and no control characters below U+0020.
_UNICODE_SPACE = re.compile("[\t-\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]")
_NAME_FORBIDDEN = re.compile("[\x00-\x1f+]")
# The signed-note signature line; the name holds no space, so the first space ends it.
SIGNATURE_LINE = re.compile("\u2014 ([^ ]+) ([A-Za-z0-9+/]+={0,2})\\Z")


def cosigner_name(name):
    if not isinstance(name, str) or not name or _NAME_FORBIDDEN.search(name) or _UNICODE_SPACE.search(name):
        return False
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 255


def witness_key_id(name, raw_public):
    """The signed-note key ID of a cosignature/v1 key: SHA-256(name || "\\n" || 0x04 || public key)[:4]."""
    return hashlib.sha256(name.encode("utf-8") + b"\n" + b"\x04" + raw_public).digest()[:4].hex()


def _plain_base64(text):
    if not isinstance(text, str) or len(text) % 4 or not re.match(r"[A-Za-z0-9+/]*={0,2}\Z", text, re.ASCII):
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    return data if base64.b64encode(data).decode("ascii") == text else None


def read_witness_key(vkey):
    """vkey: <name>+<hex key id>+<base64(0x04 || Ed25519 public key)>, as signed-note writes it."""
    # The name and key id hold no "+"; the base64 key may, so split at the first two only.
    parts = vkey.split("+", 2) if isinstance(vkey, str) else []
    if len(parts) != 3 or not cosigner_name(parts[0]) or not re.match(r"[0-9a-f]{8}\Z", parts[1], re.ASCII):
        raise Rejected("witness-policy", "a witness key is not <name>+<key id>+<key>")
    data = _plain_base64(parts[2])
    if data is None or len(data) != 33 or data[0] != 4:
        raise Rejected("witness-policy", "witness %s: not a cosignature/v1 Ed25519 key" % parts[0])
    if witness_key_id(parts[0], data[1:]) != parts[1]:
        raise Rejected("witness-policy", "witness %s: key id does not match the key" % parts[0])
    return {"name": parts[0], "keyId": parts[1], "public": data[1:]}


def _witness_policy(witnesses, quorum):
    if witnesses is None:
        return None
    if not isinstance(witnesses, list) or not witnesses or len(witnesses) > LIMITS["witnesses"]:
        raise Rejected("witness-policy", "witnesses must be a list of 1 to 64 vkeys")
    keys = [read_witness_key(v) for v in witnesses]
    if len(set(k["name"] for k in keys)) != len(keys):
        raise Rejected("witness-policy", "two witness keys share a name")
    # C2SP: distinct cosigners use distinct Ed25519 keys, so one key under two names is refused.
    if len(set(k["public"] for k in keys)) != len(keys):
        raise Rejected("witness-policy", "two witness names share a key")
    k = len(keys) if quorum is None else quorum
    if not _int(k) or k < 1 or k > len(keys):
        raise Rejected("witness-policy", "quorum must be between 1 and the number of witnesses")
    return {"keys": keys, "quorum": k}


def _examine_cosignatures(state, policy, cosignatures, check_signature):
    """As examineCosignatures in verify.mjs: unknown keys are counted and ignored, a trusted key's
    cosignature must verify, and must name a tree this ledger has (else rollback or fork)."""
    origin, valid, ignored = cosignature_origin(state["meta"]["log"]), [], 0
    for text in _lines(cosignatures or b"", LIMITS["cosignatures"], "cosignature-shape"):
        line = _canonical(text, "cosignature-shape", "cosignature-shape")
        if (not _exact(line, ("treeSize", "rootHash", "cosignature")) or not _int(line["treeSize"]) or line["treeSize"] < 1
                or line["treeSize"] > LIMITS["entries"] or not isinstance(line["rootHash"], str) or not HEX64.match(line["rootHash"])
                or not isinstance(line["cosignature"], str)):
            raise Rejected("cosignature-shape")
        match = SIGNATURE_LINE.match(line["cosignature"])
        data = _plain_base64(match.group(2)) if match and cosigner_name(match.group(1)) else None
        if data is None or len(data) != 76:
            raise Rejected("cosignature-shape", "not a signed-note cosignature line")
        name, key_id, time = match.group(1), data[:4].hex(), int.from_bytes(data[4:12], "big")
        if time > 2 ** 53 - 1:
            raise Rejected("cosignature-shape", "time")
        trusted = next((k for k in policy["keys"] if k["name"] == name and k["keyId"] == key_id), None)
        if trusted is None:
            ignored += 1
            continue
        message = cosigned_message(time, checkpoint_note(origin, line["treeSize"], line["rootHash"]))
        if not check_signature(trusted["public"], message, data[12:]):
            raise Rejected("cosignature-invalid", "witness %s at size %d" % (name, line["treeSize"]))
        valid.append({"witness": name, "treeSize": line["treeSize"], "rootHash": line["rootHash"], "time": time,
                      "message": message, "signature": data[12:], "public": trusted["public"]})
    leaves = state["leaves"]
    beyond = next((c for c in valid if c["treeSize"] > len(leaves)), None)
    if beyond:
        raise Rejected("witness-rollback", "witness %s cosigned %d entries; this ledger has %d" % (beyond["witness"], beyond["treeSize"], len(leaves)))
    heads = tree_heads_at(leaves, sorted(set(c["treeSize"] for c in valid)))
    forked = next((c for c in valid if heads[c["treeSize"]].hex() != c["rootHash"]), None)
    if forked:
        raise Rejected("witness-fork", "witness %s cosigned a different tree at size %d" % (forked["witness"], forked["treeSize"]))
    by_size = {}
    for c in valid:
        by_size.setdefault(c["treeSize"], set()).add(c["witness"])
    sizes = sorted(by_size)
    met = [size for size in sizes if len(by_size[size]) >= policy["quorum"]]
    return {"origin": origin, "quorum": policy["quorum"], "trusted": [k["name"] for k in policy["keys"]], "witnessedSize": met[-1] if met else None,
            "latestCheckpointWitnessed": state["points"][-1]["treeSize"] in met,
            "cosigned": [{"treeSize": size, "witnesses": sorted(by_size[size])} for size in sizes], "ignored": ignored, "valid": valid}


def _cosignature_controls(state, check_signature):
    """The cosignature path checks itself: a flipped signature, and a valid one moved to another size."""
    witnessing = state.get("witnessing")
    if not witnessing or not witnessing["valid"]:
        return []
    c = witnessing["valid"][0]
    moved = cosigned_message(c["time"], checkpoint_note(witnessing["origin"], c["treeSize"] + 1, c["rootHash"]))
    controls = [("cosignature-tampered", lambda: check_signature(c["public"], c["message"], _flip(c["signature"]))),
                ("cosignature-moved", lambda: check_signature(c["public"], moved, c["signature"]))]
    return [{"id": name, "expected": "rejected", "observed": "accepted" if attempt() is True else "rejected"} for name, attempt in controls]


def verify_ledger(metadata, entries, checkpoints, envelopes, ledger_pem, evidence_pem=None, check_signature=None, run_files=None,
                  cosignatures=None, witnesses=None, quorum=None):
    check_signature = check_signature or attest.ed25519_verify
    public, keyid = attest.public_key_from_pem(ledger_pem)
    evidence_pem = evidence_pem or ledger_pem
    attest.public_key_from_pem(evidence_pem)
    try:
        policy = _witness_policy(witnesses, quorum)
        state = _examine(metadata, entries, checkpoints, envelopes, public, keyid, evidence_pem, check_signature, run_files)
        if policy:
            state["witnessing"] = _examine_cosignatures(state, policy, cosignatures, check_signature)
    except Rejected as error:
        return {"ledger": LEDGER_VERSION, "verified": False, "verdict": "rejected", "reason": error.reason, "detail": str(error), "keyid": keyid, "selfChecks": []}
    checks = _negative_controls(state, public, check_signature) + _cosignature_controls(state, check_signature)
    failed = [c["id"] for c in checks if c["observed"] != "rejected"]
    covered = state["points"][-1]["treeSize"]
    witnessing = state.get("witnessing")
    witness = ({"quorum": witnessing["quorum"], "witnessedSize": witnessing["witnessedSize"], "latestCheckpointWitnessed": witnessing["latestCheckpointWitnessed"]}
               if witnessing and witnessing["witnessedSize"] else "none")
    return {"ledger": LEDGER_VERSION, "verified": not failed, "verdict": "self-check-failed" if failed else "verified",
            "reason": "negative-control-accepted" if failed else None,
            "detail": "This verifier accepted tampered input (%s); do not rely on it." % ", ".join(failed) if failed else None,
            "keyid": keyid, "log": state["meta"]["log"], "size": len(state["entries"]), "covered": covered,
            "unsignedTail": len(state["entries"]) - covered, "witness": witness,
            "witnessCoverage": "no-policy" if not witnessing else "met" if witnessing["witnessedSize"] else "not-met",
            **({"witnessing": {k: v for k, v in witnessing.items() if k != "valid"}} if witnessing else {}),
            "verdictsCheckedAgainstRunFiles": state["verdictsChecked"], "runs": state["runCount"],
            "checkpoints": [{"treeSize": p["treeSize"], "rootHash": p["rootHash"], "signedAt": p["signedAt"]} for p in state["points"]],
            "selfChecks": checks}


def verify_inclusion_path(leaf, index, tree_size, path, root):
    """RFC 9162 section 2.1.3.2."""
    if not (_int(index) and _int(tree_size)) or index < 0 or index >= tree_size or len(path) > LIMITS["proofLength"]:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency_path(first, second, path, first_root, second_root):
    """RFC 9162 section 2.1.4.2, with the equal-size case made explicit."""
    if not (_int(first) and _int(second)) or first < 1 or first > second or len(path) > LIMITS["proofLength"]:
        return False
    if first == second:
        return not path and first_root == second_root
    if not path:
        return False
    items = [first_root] + list(path) if first & (first - 1) == 0 else list(path)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = items[0]
    for c in items[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def _hex_list(items, reason):
    if not isinstance(items, list) or len(items) > LIMITS["proofLength"] or not all(isinstance(h, str) and HEX64.match(h) for h in items):
        raise Rejected(reason, "path")
    return [bytes.fromhex(h) for h in items]


def _result(attempt, keyid):
    try:
        out = {"verified": True, "verdict": "verified", "reason": None, "keyid": keyid}
        out.update(attempt())
        return out
    except Rejected as error:
        return {"verified": False, "verdict": "rejected", "reason": error.reason, "detail": str(error), "keyid": keyid}


def _js_int(value):
    """A proof number as JavaScript's JSON.parse reads it: 1.0 and 1 are the same safe integer."""
    if isinstance(value, float) and value.is_integer() and abs(value) <= 2 ** 53 - 1:
        return int(value)
    return value if _int(value) else None


def _proof_file(path):
    """A proof file as a proof, or None (an invalid proof) when it is not JSON this verifier can hold."""
    return read_proof(_read(path, 16 * 1024 * 1024))


def read_proof(text):
    """A proof file, or None when it is not JSON both verifiers read (deep nesting included)."""
    try:
        text = text.decode("utf-8") if isinstance(text, bytes) else text
    except UnicodeDecodeError:
        return None
    if too_deep(text):
        return None
    try:
        return json_js(text)
    except (ValueError, RecursionError):
        return None


# A string, or a number token, of JSON text. Strings come first, so a number inside one is never a token. A string
# with no closing quote runs to the end of the text (still not JSON), so the pattern never backtracks: it is linear.
_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\[\s\S])*(?:"|\\?\Z)|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')


def _long_integers_as_infinity(text, limit=309):
    """The text with each integer token longer than `limit` digits, outside strings, written as 1e400 or -1e400.
    No double holds 10**309 or more, so JavaScript reads such an integer as an infinity, and attest's json.loads then
    does too. That keeps Python's integer-digit limit (never below 640 digits; 4300 by default in 3.11 and later and
    some earlier security releases) from applying to any number, in linear time, with nothing changed in the
    interpreter. A token with a leading zero is left alone: it is not JSON in either language."""
    def token(match):
        value = match.group(0)
        digits = value.lstrip("-")
        if value[0] == '"' or len(digits) <= limit or digits[0] == "0" or not digits.isdigit():
            return value
        return "-1e400" if value[0] == "-" else "1e400"
    return _JSON_TOKEN.sub(token, text)


def _is_payments(run):
    return run.get("schema") == attest.PAYMENTS_RUN_SCHEMA


def _run_results(data, payments=False):
    """The [id, status] list of a run file, or None unless results is a list of objects with a
    string id and status, the way a run export writes it. A payments-pack run's list is its rows',
    read only from a run that passes attest's payments checks (verify.mjs runFileVerdicts)."""
    try:
        text = data.decode("utf-8")
        if too_deep(text):
            return None
        if payments:
            run = attest._saved_run("run file", _long_integers_as_infinity(text).encode("utf-8"))
            return [[row["id"], row["status"]] for row in run[2]["rows"]] if run is not None and run[0] else None
        results = json_js(text)["results"]
    except (Rejected, ValueError, UnicodeError, RecursionError, KeyError, TypeError):
        return None
    if not isinstance(results, list) or not all(isinstance(r, dict) and isinstance(r.get("id"), str) and isinstance(r.get("status"), str) for r in results):
        return None
    return [[r["id"], r["status"]] for r in results]


def verify_inclusion(entry_line, proof, checkpoint, ledger_pem):
    public, keyid = attest.public_key_from_pem(ledger_pem)

    def attempt():
        point = read_checkpoint(_trimmed(checkpoint), public, keyid)
        line = entry_line[:-1] if entry_line.endswith("\n") else entry_line
        entry = _canonical(line, "entry-shape", "entry-not-canonical")
        _entry_shape(entry)
        if (not _exact(proof, ("_type", "log", "index", "treeSize", "path")) or proof["_type"] != INCLUSION_VERSION or proof["log"] != point["log"]
                or _js_int(proof["index"]) is None or _js_int(proof["treeSize"]) is None):
            raise Rejected("inclusion-proof-invalid", "shape")
        if _js_int(proof["index"]) != entry["index"] or _js_int(proof["treeSize"]) != point["treeSize"]:
            raise Rejected("inclusion-proof-invalid", "the proof is for another entry or tree size")
        if not verify_inclusion_path(leaf_hash(line.encode("utf-8")), entry["index"], point["treeSize"], _hex_list(proof["path"], "inclusion-proof-invalid"),
                                     bytes.fromhex(point["rootHash"])):
            raise Rejected("inclusion-proof-invalid")
        return {"log": point["log"], "index": entry["index"], "treeSize": point["treeSize"], "witness": "none"}
    return _result(attempt, keyid)


def verify_consistency(older, newer, proof, ledger_pem):
    public, keyid = attest.public_key_from_pem(ledger_pem)

    def attempt():
        a = read_checkpoint(_trimmed(older), public, keyid)
        b = read_checkpoint(_trimmed(newer), public, keyid, a["log"])
        if a["treeSize"] == b["treeSize"] and (a["rootHash"] != b["rootHash"] or a["headHash"] != b["headHash"]):
            raise Rejected("fork", "two signed heads at size %d" % a["treeSize"])
        if b["treeSize"] < a["treeSize"] or _at(b["signedAt"]) < _at(a["signedAt"]):
            raise Rejected("checkpoint-regression")
        if (not _exact(proof, ("_type", "log", "from", "to", "path")) or proof["_type"] != CONSISTENCY_VERSION or proof["log"] != a["log"]
                or _js_int(proof["from"]) is None or _js_int(proof["to"]) is None
                or _js_int(proof["from"]) != a["treeSize"] or _js_int(proof["to"]) != b["treeSize"]):
            raise Rejected("consistency-proof-invalid", "shape")
        if not verify_consistency_path(a["treeSize"], b["treeSize"], _hex_list(proof["path"], "consistency-proof-invalid"),
                                       bytes.fromhex(a["rootHash"]), bytes.fromhex(b["rootHash"])):
            raise Rejected("consistency-proof-invalid", "the newer checkpoint does not extend the older one")
        return {"log": a["log"], "from": a["treeSize"], "to": b["treeSize"], "witness": "none"}
    return _result(attempt, keyid)


def _read(path, limit):
    return attest.read_bounded(path, limit)


def _read_ledger(directory):
    envelopes = {}
    folder = os.path.join(directory, "envelopes")
    for name in sorted(os.listdir(folder)):
        if re.match(r"[0-9a-f]{64}\.json\Z", name, re.ASCII):
            envelopes[name[:64]] = _read(os.path.join(folder, name), 2 * 1024 * 1024)
    return (_read(os.path.join(directory, "ledger.json"), 4096), _read(os.path.join(directory, "entries.jsonl"), LIMITS["entries"] * LIMITS["lineBytes"]),
            _read(os.path.join(directory, "checkpoints.jsonl"), LIMITS["checkpoints"] * LIMITS["lineBytes"]), envelopes)


def _read_cosignatures(directory):
    """Witness cosignatures (optional): cosignatures.jsonl, or nothing when the file is absent."""
    path = os.path.join(directory, "cosignatures.jsonl")
    return _read(path, LIMITS["checkpoints"] * LIMITS["lineBytes"]) if os.path.lexists(path) else b""


def _witness_keys(data):
    """One vkey per line, as cli.mjs reads them: spaces and tabs around a line are dropped, blank lines
    and comments ("#" alone, or "#" then a space or tab) are skipped, and every other line is a vkey.
    A vkey holds no space, so a name may start with "#"; a key disabled as "#vkey" fails loudly."""
    lines = [line[:-1] if line.endswith("\r") else line for line in data.decode("utf-8", errors="replace").split("\n")]
    lines = [line.strip(" \t") for line in lines]
    return [line for line in lines if line and line != "#" and not line.startswith(("# ", "#\t"))]


def _text(path):
    """An input file as text. Invalid UTF-8 becomes U+FFFD, as Node's Buffer.toString does, so it
    reaches the verifier and is judged there rather than failing as a file error."""
    return _read(path, 16 * 1024 * 1024).decode("utf-8", errors="replace")


USAGE = ("Usage: verify_ledger.py log --key PUB --ledger DIR [--evidence-key PUB] [--run-files DIR] [--witnesses FILE [--quorum K]] | inclusion --key PUB --entry FILE --proof FILE "
         "--checkpoint FILE | consistency --key PUB --older FILE --newer FILE --proof FILE")


def main(argv):
    if not argv:
        print(json.dumps({"error": USAGE}, indent=2))
        return 2
    command, args = argv[0], argv[1:]
    flags = {"log": ("--key", "--ledger", "--evidence-key", "--run-files", "--witnesses", "--quorum"), "inclusion": ("--key", "--entry", "--proof", "--checkpoint"),
             "consistency": ("--key", "--older", "--newer", "--proof")}
    try:
        if command not in flags or len(args) % 2:
            raise ValueError(USAGE)
        options = {}
        for i in range(0, len(args), 2):
            if args[i] not in flags[command] or args[i] in options:
                raise ValueError(USAGE)
            options[args[i]] = args[i + 1]
        required = [f for f in flags[command] if f not in ("--evidence-key", "--run-files", "--witnesses", "--quorum")]
        if any(f not in options for f in required):
            raise ValueError(USAGE)
        # Paths are absolute, as for the Node CLI.
        if "--quorum" in options and ("--witnesses" not in options or not re.match(r"[1-9][0-9]{0,2}\Z", options["--quorum"], re.ASCII)):
            raise ValueError("--quorum is a whole number, given with --witnesses.")
        if any(not os.path.isabs(value) for flag, value in options.items() if flag != "--quorum"):
            raise ValueError("Paths must be absolute.")
        key = _read(options["--key"], 16384).decode("utf-8")
        if command == "log":
            evidence = _read(options["--evidence-key"], 16384).decode("utf-8") if "--evidence-key" in options else None
            run_files = None
            if "--run-files" in options:
                run_files = {}
                for name in sorted(os.listdir(options["--run-files"])):
                    path = os.path.join(options["--run-files"], name)
                    if os.path.isfile(path) and not os.path.islink(path):
                        data = _read(path, 8 * 1024 * 1024)
                        run_files[hashlib.sha256(data).hexdigest()] = data
            witnesses = _witness_keys(_read(options["--witnesses"], 65536)) if "--witnesses" in options else None
            quorum = int(options["--quorum"]) if "--quorum" in options else None
            result = verify_ledger(*_read_ledger(options["--ledger"]), key, evidence, run_files=run_files,
                                   cosignatures=_read_cosignatures(options["--ledger"]), witnesses=witnesses, quorum=quorum)
        elif command == "inclusion":
            result = verify_inclusion(_text(options["--entry"]), _proof_file(options["--proof"]), _text(options["--checkpoint"]), key)
        else:
            result = verify_consistency(_text(options["--older"]), _text(options["--newer"]), _proof_file(options["--proof"]), key)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as error:
        print(json.dumps({"error": str(error) or type(error).__name__}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return {"verified": 0, "rejected": 1}.get(result["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
