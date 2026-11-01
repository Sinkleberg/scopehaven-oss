#!/usr/bin/env python3
"""Independent verifier for Scopehaven signed evidence (scopehaven-attest/1).

Standard library only (Python 3.8+). It shares no code with the Node signer or
verifier: Ed25519 (RFC 8032), the DSSE pre-authentication encoding, the in-toto
Statement checks and the run identity recomputation are written out here.

    python3 verify_envelope.py --key scopehaven-signing-key.pub.pem \
        --envelope evidence.dsse.json (--dir DIR | FILE...) \
        [--scopehaven-keys scopehaven-keys.json --countersignature evidence.countersign.dsse.json \
         --timestamp evidence.countersign.tsr]

A signature shows that the key holder produced these exact files. It does not
show that the checks, the application or the results inside them are correct.
Run identities in the statement (native run exports and payments-pack runs) are
recomputed from the run files, never trusted.
The result's "builds" names the build that packed these files (from the signed
statement) and the build that ran each run (from the run's own file), separately:
a pack can be made by another version. Each is what that install said of itself.
After an envelope passes, negative controls must be rejected by the same code,
and a published RFC 8032 test vector must be accepted; otherwise the verdict is
self-check-failed.
With the three countersignature options it then checks ScopeHaven's countersignature
(scopehaven-countersign/1) against ScopeHaven's published key set, and its RFC 3161
timestamp against the TSA roots pinned there, with its own DER reader, RSA and ECDSA
(P-256, P-384); the countersignature has its own negative controls.

Exit codes: 0 verified, 1 rejected, 2 usage or file error, 3 self-check failed.
"""
import base64
import binascii
import hashlib
import json
import math
import os
import re
import stat
import sys
from datetime import datetime, timezone
from decimal import Decimal

ATTEST_VERSION = "scopehaven-attest/1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://scopehaven.dev/attestation/evidence-export/v1"
MEANING = ("The holder of this signing key produced these exact files. The signature does not show "
           "that the checks, the application or the results inside them are correct.")
CLOCK = "Signer's local clock; not a trusted timestamp."
RUN_FIELDS = ("id", "schemaVersion", "createdAt", "targetId", "build", "suiteId", "suiteHash", "policyHash",
              "fixtureVersion", "fixtureHash", "applicationId", "adapterVersion", "evaluatorHash", "targetBuildHash",
              "targetConfigHash", "runtimeMode", "evidenceOrigin", "assertionSchemaVersion", "contextId", "profileHash",
              "scopeLabel")
# A payments-pack run, read by the rules of the pack's own reader (integrations/payments-pack/output.mjs
# savedPaymentsRun), written out here as in verify.mjs.
PAYMENTS_RUN_SCHEMA = "scopehaven-payments-run/1"
PAYMENTS_SCOPE = ("Owned or operator-run app on loopback, judged from a Stripe-shaped test-mode payments double the app "
                  "cannot edit. No real provider, no live money, no production assurance.")
PAYMENTS_RUN_FIELDS = ("id", "schema", "startedAt", "finishedAt", "targetId", "applicationId", "build", "packSha256")
PAYMENTS_KEYS = ("schema", "id", "targetId", "applicationId", "name", "build", "packSha256", "startedAt", "finishedAt", "scope",
                 "provider", "authorization", "counts", "rows", "settlement", "sha256")
PRODUCER_KEYS = ("name", "version", "attest")
RELEASE_KEYS = ("source", "version", "commit", "manifestSha256")
PAYMENTS_RUN_ID = re.compile(r"pay-[0-9]{14}-[0-9a-f]{8}\Z", re.ASCII)
CHECK_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
STATUSES = ("pass", "fail", "inconclusive")
ROLES = ("boundary", "control")
LIMITS ={"subjects": 64, "subjectBytes": 8 * 1024 * 1024, "envelopeBytes": 2 * 1024 * 1024, "payloadBytes": 1024 * 1024}
SUBJECT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
VERSION = re.compile(r"\d+\.\d+\.\d+\Z", re.ASCII)
ISO = re.compile(r"2\d{3}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z", re.ASCII)  # years 2000-2999, as in verify.mjs
BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z", re.ASCII)
ARRAY_INDEX = re.compile(r"(0|[1-9][0-9]*)\Z", re.ASCII)
# DER prefix of an X.509 SubjectPublicKeyInfo holding a 32-byte Ed25519 key (RFC 8410).
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")


class Rejected(Exception):
    def __init__(self, reason, detail=None):
        super().__init__("%s: %s" % (reason, detail) if detail else reason)
        self.reason = reason


# ---- Ed25519 verification (RFC 8032 section 5.1), extended coordinates ----
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1 = (y1 - x1) * (y2 - x2) % P
    e2 = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = e2 - e1, dd - c, dd + c, e2 + e1
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _compress(point):
    zinv = pow(point[2], P - 2, P)
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, P - 2, P) % P
_GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202  # recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def ed25519_public(seed):
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return _compress(_mul(scalar, BASE))


IDENTITY = (0, 1, 1, 0)


def _small_order(point):
    return _equal(_mul(8, point), IDENTITY)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    # A small-order key or R lets anyone satisfy the group equation; OpenSSL refuses them too.
    if a is None or r is None or _small_order(a) or _small_order(r):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return _equal(_mul(s, BASE), _add(r, _mul(k, a)))


# RFC 8032 section 7.1, TEST 1 (empty message): a known answer that must verify.
RFC8032_TEST1 = (bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"), b"",
                 bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"))


# ---- DSSE, JSON and the store's canonical digest ----
def pae(payload_type, body):
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(kind), kind, len(body)) + body


class NotJSON(ValueError):
    """Text JavaScript's JSON.parse would also refuse."""


def _no_constants(name):
    raise NotJSON("non-JSON constant " + name)


def _json(data):
    """Strict JSON from UTF-8 bytes, matching JavaScript's JSON.parse acceptance.
    Raises NotJSON (or UnicodeDecodeError) for what JavaScript also refuses; RecursionError
    or another ValueError means valid JSON beyond this parser's limits."""
    try:
        return json.loads(data.decode("utf-8"), parse_constant=_no_constants)
    except json.JSONDecodeError as error:
        raise NotJSON(str(error))


def _js_json(value):
    """JavaScript JSON.stringify(JSON.parse(text)) with no spacing: integer-like keys
    first in numeric order (as JavaScript objects keep them), numbers as JavaScript prints them."""
    if isinstance(value, list):
        return "[" + ",".join(_js_json(item) for item in value) + "]"
    if isinstance(value, dict):
        # An array index has at most 10 digits, so int() never sees a longer key (Python 3.11+ refuses over 4300).
        index = sorted((key for key in value if ARRAY_INDEX.match(key) and len(key) <= 10 and int(key) < 2 ** 32 - 1), key=int)
        named = set(index)
        keys = index + [key for key in value if key not in named]
        return "{" + ",".join(_js_string(key) + ":" + _js_json(value[key]) for key in keys) + "}"
    return _js_scalar(value)


def _canonical_json(value):
    return _js_json(value).encode("utf-8")


def _js_string(text):
    out = json.dumps(text, ensure_ascii=False)
    # JSON.stringify escapes lone surrogates; json.dumps leaves them raw.
    return "".join("\\u%04x" % ord(ch) if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in out)


def _js_number(value):
    """JSON.stringify of the double JavaScript's JSON.parse makes from this number."""
    if isinstance(value, int):
        if abs(value) < 2 ** 53:
            return str(value)
        try:
            value = float(value)
        except OverflowError:
            return "null"
    if math.isinf(value) or math.isnan(value):
        return "null"
    if value == 0:
        return "0"
    sign, digits, exponent = Decimal(repr(value)).normalize().as_tuple()
    text = "".join(map(str, digits))
    k, n = len(text), len(text) + int(exponent)
    prefix = "-" if sign else ""
    if k <= n <= 21:
        return prefix + text + "0" * (n - k)
    if 0 < n <= 21:
        return prefix + text[:n] + "." + text[n:]
    if -6 < n <= 0:
        return prefix + "0." + "0" * (-n) + text
    e = n - 1
    mantissa = text if k == 1 else text[0] + "." + text[1:]
    return prefix + mantissa + "e" + ("+" if e >= 0 else "-") + str(abs(e))


def _stable(value):
    """src/domain.mjs stable(): sorted keys by UTF-16 code units, JSON.stringify leaves."""
    if isinstance(value, list):
        return "[" + ",".join(_stable(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_js_string(key) + ":" + _stable(value[key]) for key in keys) + "}"
    return _js_scalar(value)


def _js_scalar(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return _js_number(value)
    return _js_string(value)


def _exact_keys(value, keys):
    return isinstance(value, dict) and len(value) == len(keys) and all(key in value for key in keys)


def _strict_base64(text, what):
    if not isinstance(text, str) or len(text) % 4 or not BASE64.match(text):
        raise Rejected("base64", what)
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise Rejected("base64", what)
    if base64.b64encode(data).decode("ascii") != text:
        raise Rejected("base64", what)
    return data


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _scalar(value):
    return value is None or isinstance(value, (str, bool, int, float))


def _iso_time(value):
    """verify.mjs isoTime: years 2000-2999 with milliseconds and Z, a real moment, printed back the same."""
    if not isinstance(value, str) or not ISO.match(value):
        return False
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (moment.year, moment.month, moment.day, moment.hour, moment.minute,
                                                   moment.second, moment.microsecond // 1000) == value


def _core_digest(name, core):
    try:
        return _sha256(_stable(core).encode("utf-8"))
    except RecursionError:
        raise Rejected("subject-unparseable", "%s is nested too deeply to recompute" % name)
    except (UnicodeEncodeError, ValueError):
        raise Rejected("run-integrity-mismatch", "%s cannot be recomputed" % name)


def _one_of(value, options):
    # JavaScript's options.includes(value), for options that are strings.
    return isinstance(value, str) and value in options


def _same_number(value, number):
    # JavaScript's value === number for a JSON value.
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == number


def _worst(statuses):
    return "fail" if "fail" in statuses else "inconclusive" if "inconclusive" in statuses else "pass"


def _readable_row(row):
    """verify.mjs readableRow: the pack's rule for a row's status."""
    if not (isinstance(row, dict) and isinstance(row.get("id"), str) and CHECK_ID.match(row["id"])
            and _one_of(row.get("status"), STATUSES) and _one_of(row.get("severity"), ROLES) and isinstance(row.get("rule"), str)
            and isinstance(row.get("standards"), list) and isinstance(row.get("request"), dict) and isinstance(row.get("assertions"), list)
            and row["assertions"] and all(isinstance(item, dict) and _one_of(item.get("status"), STATUSES) for item in row["assertions"])):
        return False
    if row["status"] != _worst([item["status"] for item in row["assertions"]]):
        return False
    effect = "tag" if row["severity"] == "control" else "withheld"
    if not isinstance(row.get("settlement"), list) or not all(isinstance(item, dict) and item.get("effect") == effect for item in row["settlement"]):
        return False
    reach = row.get("reach")
    return row["status"] != "pass" or (isinstance(reach, dict) and reach.get("reached") is True
                                       and (row["severity"] == "control" or not row["settlement"]))


def _payments_run(name, value):
    """verify.mjs paymentsRun: the body of a payments run that passes the pack's reader, checked in its order."""
    def refused(detail):
        return Rejected("payments-run-refused", "%s %s" % (name, detail))

    run = {key: item for key, item in value.items() if key != "comparison"}
    core = {key: item for key, item in run.items() if key != "sha256"}
    if not isinstance(run.get("id"), str) or not PAYMENTS_RUN_ID.match(run["id"]):
        raise refused("has no payments run id")
    core_sha256 = _core_digest(name, core)
    if not isinstance(run.get("sha256"), str) or core_sha256 != run["sha256"]:
        raise Rejected("run-integrity-mismatch", "%s was edited after it was produced" % name)
    keys = PAYMENTS_KEYS + ("producer",) if "producer" in run else PAYMENTS_KEYS  # Runs saved before F9 have no producer.
    if len(run) != len(keys) or any(key not in run for key in keys):
        raise refused("does not have exactly the fields a payments run has")
    if run["scope"] != PAYMENTS_SCOPE:
        raise refused("does not state the payments pack's scope")
    rows = run["rows"]
    if not isinstance(rows, list) or not rows or not all(_readable_row(row) for row in rows) or len(set(row["id"] for row in rows)) != len(rows):
        raise refused("has a row whose status is not what its assertions, reach and settlement give")
    counts = run["counts"]
    if (not isinstance(counts, dict) or len(counts) != len(STATUSES)
            or any(not _same_number(counts.get(status), sum(1 for row in rows if row["status"] == status)) for status in STATUSES)):
        raise refused("has counts that are not its rows' statuses")
    provider = run["provider"]
    if not isinstance(provider, dict) or provider.get("livemode") is not False or not isinstance(provider.get("kind"), str):
        raise refused("does not say its provider was in test mode")
    if not _iso_time(run["startedAt"]) or not _iso_time(run["finishedAt"]):
        raise refused("has no ISO start and finish times")
    return core, core_sha256


def _valid_release(release):
    """verify.mjs validRelease: the build a statement or a run names (src/producer.mjs)."""
    if not _exact_keys(release, RELEASE_KEYS) or not isinstance(release["version"], str) or not isinstance(release["commit"], str):
        return False
    if release["version"] != "unknown" and not VERSION.match(release["version"]):
        return False
    source, commit, manifest = release["source"], release["commit"], release["manifestSha256"]
    if source == "release-manifest":
        return COMMIT.match(commit) is not None and isinstance(manifest, str) and HEX64.match(manifest) is not None
    if source == "git":
        return COMMIT.match(commit) is not None and manifest is None
    return source == "unknown" and commit == "unknown" and manifest is None


def _saved_run(name, content):
    """verify.mjs savedRun: a run export, or else any JSON object that declares the payments run schema; None otherwise."""
    # A run is a JSON object; anything else is no run, as in verify.mjs, without parsing it.
    if not content.lstrip(b" \t\r\n").startswith(b"{"):
        return None
    try:
        value = _json(content)
    except (NotJSON, UnicodeDecodeError):
        return None
    except (ValueError, RecursionError):
        # Valid JSON this parser can't hold (deep nesting, huge integers): never skip its checks.
        raise Rejected("subject-unparseable", "%s is beyond this verifier's JSON limits" % name)
    if not isinstance(value, dict):
        return None
    integrity = value.get("integrity")
    native = (value.get("schemaVersion") == 1 and not isinstance(value.get("schemaVersion"), bool)
              and isinstance(value.get("id"), str) and isinstance(value.get("suiteHash"), str)
              and isinstance(integrity, dict) and integrity.get("algorithm") == "SHA-256" and isinstance(integrity.get("sha256"), str))
    if not native and value.get("schema") != PAYMENTS_RUN_SCHEMA:
        return None
    # The negative controls re-serialize the whole run, its notes or stored comparison included, so that must work here.
    try:
        _canonical_json(value)
    except RecursionError:
        raise Rejected("subject-unparseable", "%s is nested too deeply to recompute" % name)
    if native:
        core = {key: item for key, item in value.items() if key not in ("integrity", "notes")}
        core_sha256 = _core_digest(name, core)
        if core_sha256 != integrity["sha256"]:
            raise Rejected("run-integrity-mismatch", "%s was edited after export" % name)
        return False, RUN_FIELDS, core, core_sha256
    core, core_sha256 = _payments_run(name, value)
    return True, PAYMENTS_RUN_FIELDS, core, core_sha256


def recompute_runs(subjects, files):
    """Every run among the subjects, in subject order, as (payments, identity)."""
    runs = []
    for subject in subjects:
        run = _saved_run(subject["name"], files[subject["name"]])
        if run is None:
            continue
        payments, fields, core, core_sha256 = run
        identity = {"subject": subject["name"]}
        for field in fields:
            if field in core and _scalar(core[field]):
                identity[field] = core[field]
        identity["coreSha256"] = core_sha256
        runs.append((payments, identity))
    return runs


def _same_runs(computed, stated):
    return _canonical_json(computed) == _canonical_json(stated)


def match_runs(computed, stated):
    """verify.mjs matchRuns: every run export's identity named exactly, in subject order; a payments run's may be left
    out (envelopes signed before payments runs had identities name none), and any that is named must be the recomputed one."""
    claimed = set(entry["subject"] for entry in stated if isinstance(entry, dict) and isinstance(entry.get("subject"), str))
    named = [identity for payments, identity in computed if not payments or identity["subject"] in claimed]
    if not _same_runs(named, stated):
        raise Rejected("run-identity-mismatch", "the statement does not match the run files it names")
    return named, [identity["subject"] for payments, identity in computed if payments and identity["subject"] not in claimed]


def _unclaimed_note(names):
    if not names:
        return None
    return ("The statement names no run identity for %s. The signature covers those files' bytes, and each is a well-formed "
            "payments run by the pack's own rules, but no run identity is signed for it (envelopes signed before payments runs "
            "had identities name none). None of this says whether the results are right." % ", ".join(names))


def parse_statement(payload):
    try:
        statement = _json(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Rejected("payload-json")
    try:
        canonical = _canonical_json(statement)
    except RecursionError:
        raise Rejected("payload-json", "nested beyond this verifier's limits")
    except UnicodeEncodeError:
        canonical = None
    if canonical != payload:
        raise Rejected("payload-not-canonical")
    if not _exact_keys(statement, ("_type", "subject", "predicateType", "predicate")) or statement["_type"] != STATEMENT_TYPE:
        raise Rejected("statement-shape")
    if statement["predicateType"] != PREDICATE_TYPE:
        raise Rejected("predicate-type")
    subjects, predicate, names = statement["subject"], statement["predicate"], set()
    if not isinstance(subjects, list) or not subjects or len(subjects) > LIMITS["subjects"]:
        raise Rejected("subject-shape")
    for entry in subjects:
        if (not _exact_keys(entry, ("name", "digest")) or not isinstance(entry["name"], str)
                or not SUBJECT_NAME.match(entry["name"]) or entry["name"] in names):
            raise Rejected("subject-shape")
        digest = entry["digest"]
        if not _exact_keys(digest, ("sha256",)) or not isinstance(digest["sha256"], str) or not HEX64.match(digest["sha256"]):
            raise Rejected("subject-shape", entry["name"])
        names.add(entry["name"])
    if (not _exact_keys(predicate, ("meaning", "clock", "producer", "signedAt", "runs"))
            or predicate["meaning"] != MEANING or predicate["clock"] != CLOCK):
        raise Rejected("predicate-shape")
    producer, signed_at = predicate["producer"], predicate["signedAt"]
    if ((not _exact_keys(producer, PRODUCER_KEYS)
         and not (_exact_keys(producer, PRODUCER_KEYS + ("release",)) and _valid_release(producer["release"])))
            or producer["name"] != "scopehaven"
            or not isinstance(producer["version"], str) or not VERSION.match(producer["version"])
            or producer["attest"] != ATTEST_VERSION):
        raise Rejected("predicate-shape", "producer")
    if not _iso_time(signed_at):
        raise Rejected("predicate-shape", "signedAt")
    if not isinstance(predicate["runs"], list) or len(predicate["runs"]) > len(subjects):
        raise Rejected("predicate-shape", "runs")
    return statement


def check_subjects(subjects, files):
    results = []
    for subject in subjects:
        content = files.get(subject["name"])
        if not isinstance(content, bytes):
            raise Rejected("subject-missing", subject["name"])
        if _sha256(content) != subject["digest"]["sha256"]:
            raise Rejected("subject-digest-mismatch", subject["name"])
        results.append({"name": subject["name"], "sha256": subject["digest"]["sha256"], "bytes": len(content)})
    named = set(subject["name"] for subject in subjects)
    for name in files:
        if name not in named:
            raise Rejected("unsigned-file", "%s is not covered by this signature" % name)
    return results


def public_key_from_pem(text):
    # Exactly one PEM block with nothing around it but whitespace, as verify.mjs reads it.
    lines = re.split(r"\r?\n", text.strip(" \t\r\n"))
    if (len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----"
            or not all(re.match(r"[A-Za-z0-9+/=]+\Z", line, re.ASCII) for line in lines[1:-1])):
        raise ValueError('Pass the signer\'s public key (PEM "BEGIN PUBLIC KEY"); verification never needs the private key.')
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(der) != 44 or der[:12] != SPKI_ED25519:
        raise ValueError("The trusted key must be an Ed25519 public key.")
    return der[12:], _sha256(der)


def _signed_statement(envelope, public, keyid, check_signature):
    """Envelope shape, trusted key and signature, then the statement: everything except the files."""
    if len(envelope) > LIMITS["envelopeBytes"]:
        raise Rejected("envelope-size")
    try:
        env = _json(envelope)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Rejected("envelope-json")
    if not _exact_keys(env, ("payload", "payloadType", "signatures")):
        raise Rejected("envelope-shape")
    if env["payloadType"] != PAYLOAD_TYPE:
        raise Rejected("payload-type")
    if not isinstance(env["signatures"], list) or len(env["signatures"]) != 1:
        raise Rejected("signature-count", "exactly one signature is accepted")
    entry = env["signatures"][0]
    if not _exact_keys(entry, ("keyid", "sig")) or not isinstance(entry["keyid"], str):
        raise Rejected("signature-shape")
    payload, sig = _strict_base64(env["payload"], "payload"), _strict_base64(entry["sig"], "sig")
    if len(payload) > LIMITS["payloadBytes"]:
        raise Rejected("payload-size")
    if entry["keyid"] != keyid:
        raise Rejected("keyid-mismatch", "signed by a different key than the trusted one")
    if len(sig) != 64 or not check_signature(public, pae(env["payloadType"], payload), sig):
        raise Rejected("signature-invalid")
    return {"type": env["payloadType"], "payload": payload, "sig": sig, "statement": parse_statement(payload)}


def _examine(envelope, public, keyid, files, check_signature):
    checked = _signed_statement(envelope, public, keyid, check_signature)
    statement = checked["statement"]
    subjects = check_subjects(statement["subject"], files)
    computed = recompute_runs(statement["subject"], files)
    runs, unclaimed = match_runs(computed, statement["predicate"]["runs"])
    return dict(checked, subjects=subjects, computed=computed, runs=runs, unclaimed=unclaimed)


def read_signed_statement(envelope, public_pem):
    """The signed statement alone, for a holder without the files (the evidence ledger checks old
    envelopes this way). Raises Rejected with the same reasons verify_envelope reports. It proves
    who signed which digests and run identities, not that any file still matches."""
    public, keyid = public_key_from_pem(public_pem)
    return {"keyid": keyid, "statement": _signed_statement(envelope, public, keyid, ed25519_verify)["statement"]}


def _flip(data):
    copy = bytearray(data if data else b"\0")
    copy[len(copy) >> 1] ^= 1
    return bytes(copy)


def _negative_controls(checked, public, files, check_signature):
    kind, payload, sig, statement = checked["type"], checked["payload"], checked["sig"], checked["statement"]
    computed, runs = checked["computed"], checked["runs"]
    other = ed25519_public(os.urandom(32))
    first = statement["subject"][0]["name"]

    def subject_tampered():
        tampered = dict(files)
        tampered[first] = _flip(files[first])
        try:
            check_subjects(statement["subject"], tampered)
            return True
        except Rejected:
            return False

    controls = [
        ("payload-tampered", lambda: check_signature(public, pae(kind, _flip(payload)), sig)),
        ("signature-tampered", lambda: check_signature(public, pae(kind, payload), _flip(sig))),
        ("payload-type-changed", lambda: check_signature(public, pae(kind + "+x", payload), sig)),
        ("wrong-key", lambda: check_signature(other, pae(kind, payload), sig)),
        ("subject-tampered", subject_tampered),
    ]
    # For the first run export and the first payments run: its file with one edit only its digest covers must fail the
    # recomputed checks, and a statement naming its identity (named or not in this one) with one changed digest must not match.
    # A run export gets an added field; a payments run's name changes instead, as in verify.mjs.
    for label, payments in (("run", False), ("payments-run", True)):
        target = next((run for run in computed if run[0] is payments), None)
        if target is None:
            continue
        name, last = target[1]["subject"], target[1]["coreSha256"]
        edited_run = _json(files[name])
        if payments:
            edited_run["name"] = edited_run["name"] + "." if isinstance(edited_run["name"], str) else "selfCheckEdit"
        else:
            edited_run["selfCheckEdit"] = True

        def file_edited(name=name, content=_canonical_json(edited_run)):
            try:
                recompute_runs([{"name": name}], {name: content})
                return True
            except Rejected:
                return False

        edited = [dict(identity, coreSha256=last[:-1] + ("1" if last.endswith("0") else "0")) if run is target else identity
                  for run in computed for identity in (run[1],) if run is target or any(identity is named for named in runs)]

        def identity_edited(edited=edited):
            try:
                match_runs(computed, edited)
                return True
            except Rejected:
                return False

        controls.append((label + "-file-edited", file_edited))
        controls.append((label + "-identity-edited", identity_edited))
    results = []
    for name, attempt in controls:
        try:
            accepted = attempt() is True
        except Rejected:
            accepted = False
        results.append({"id": name, "expected": "rejected", "observed": "accepted" if accepted else "rejected"})
    # A verifier that rejects everything would also pass the controls above.
    vector_public, vector_message, vector_sig = RFC8032_TEST1
    accepted = check_signature(vector_public, vector_message, vector_sig) is True
    results.append({"id": "rfc8032-test-1", "expected": "accepted", "observed": "accepted" if accepted else "rejected"})
    return results


def _builds(predicate, computed, files):
    """verify.mjs buildsOf: the build that packed these files, and the build that ran each run; None where none is recorded."""
    running = []
    for _, identity in computed:
        value = _json(files[identity["subject"]]).get("producer")
        release = value.get("release") if isinstance(value, dict) else None
        running.append({"subject": identity["subject"], "release": release if _valid_release(release) else None})
    return {"packing": predicate["producer"].get("release"), "running": running}


def verify_envelope(envelope, public_pem, files, check_signature=None):
    check_signature = check_signature or ed25519_verify
    public, keyid = public_key_from_pem(public_pem)
    try:
        checked = _examine(envelope, public, keyid, files, check_signature)
    except Rejected as error:
        return {"attest": ATTEST_VERSION, "verified": False, "verdict": "rejected", "reason": error.reason,
                "detail": str(error), "keyid": keyid, "selfChecks": []}
    self_checks = _negative_controls(checked, public, files, check_signature)
    failed = [check["id"] for check in self_checks if check["observed"] != check["expected"]]
    predicate = checked["statement"]["predicate"]
    return {"attest": ATTEST_VERSION, "verified": not failed, "verdict": "self-check-failed" if failed else "verified",
            "reason": "negative-control-accepted" if failed else None,
            "detail": "This verifier gave the wrong answer on a control (%s); do not rely on it." % ", ".join(failed) if failed else None,
            "keyid": keyid, "meaning": predicate["meaning"], "signedAt": predicate["signedAt"], "clock": predicate["clock"],
            "producer": predicate["producer"], "builds": _builds(predicate, checked["computed"], files),
            "subjects": checked["subjects"], "runs": checked["runs"],
            "unclaimedRuns": checked["unclaimed"], "note": _unclaimed_note(checked["unclaimed"]), "selfChecks": self_checks}


def subject_names(envelope):
    try:
        statement = _json(_strict_base64(_json(envelope)["payload"], "payload"))
        names = [entry.get("name") for entry in statement["subject"] if isinstance(entry, dict)]
    except (ValueError, UnicodeDecodeError, RecursionError, Rejected, KeyError, TypeError, AttributeError):
        return []
    unique = []
    for name in names:
        if isinstance(name, str) and SUBJECT_NAME.match(name) and name not in unique:
            unique.append(name)
    return unique[:LIMITS["subjects"]]


# ---- RFC 3161 timestamps and ScopeHaven's countersignature (scopehaven-countersign/1) ----
# The envelope above is the operator's: the first signature. ScopeHaven then countersigns hashes only (the SHA-256 of that
# envelope's statement, its signer's key id and the SHA-256 of its signature), and a public TSA's RFC 3161 token stamps the
# SHA-256 of the countersignature. The countersigning key must be in ScopeHaven's published key set (scopehaven-keys/1), and
# the TSA's certificate must chain to a root pinned there. Written out here independently of verify-countersign.mjs.
COUNTERSIGN_VERSION = "scopehaven-countersign/1"
COUNTERSIGN_PREDICATE = "https://scopehaven.dev/attestation/countersignature/v1"
COUNTERSIGN_MEANING = ("ScopeHaven countersigned the SHA-256 of this evidence statement and of its first signature, at the request "
                       "of the named licence. ScopeHaven saw no file, row or result. The countersignature does not show that "
                       "ScopeHaven ran the checks, or that the checks, the application or the results are correct.")
COUNTERSIGN_CLOCK = "ScopeHaven countersigner's clock; the RFC 3161 timestamp is the trusted time."
KEYSET_SCHEMA = "scopehaven-keys/1"
KEYSET_URL = "https://scopehaven.dev/.well-known/scopehaven-keys.json"
COUNTERSIGNER = {"name": "ScopeHaven", "keys": KEYSET_URL}
STATEMENT_SUBJECT = "evidence-statement"
CLOCK_SKEW_SECONDS = 300
LICENCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
KEY_STATUSES = ("active", "interim", "retired", "revoked")
COUNTERSIGN_LIMITS = {"envelopeBytes": 64 * 1024, "timestampBytes": 64 * 1024, "keysetBytes": 256 * 1024}


def _bad(detail):
    raise Rejected("timestamp-invalid", detail)


class _Node(object):
    __slots__ = ("data", "tag", "start", "body", "end")

    def __init__(self, data, tag, start, body, end):
        self.data, self.tag, self.start, self.body, self.end = data, tag, start, body, end

    @property
    def raw(self):
        return self.data[self.start:self.end]

    @property
    def value(self):
        return self.data[self.body:self.end]


def _tlv(data, pos, limit):
    """One DER element, strictly: definite lengths in their shortest form, no high tag numbers."""
    if pos + 2 > limit:
        _bad("truncated DER")
    tag, length, body = data[pos], data[pos + 1], pos + 2
    if tag & 0x1F == 0x1F:
        _bad("high tag numbers are not used")
    if length & 0x80:
        count = length & 0x7F
        if count < 1 or count > 4 or body + count > limit or data[body] == 0:
            _bad("length is not in DER form")
        length = int.from_bytes(data[body:body + count], "big")
        if length < 128:
            _bad("length is not in DER form")
        body += count
    if body + length > limit:
        _bad("truncated DER")
    return _Node(data, tag, pos, body, body + length)


def _der(data):
    node = _tlv(data, 0, len(data))
    if node.end != len(data):
        _bad("trailing bytes after DER")
    return node


def _kids(node):
    if not node.tag & 0x20:
        _bad("expected a constructed value")
    out, pos = [], node.body
    while pos < node.end:
        kid = _tlv(node.data, pos, node.end)
        out.append(kid)
        pos = kid.end
    return out


def _expect(node, tag, what):
    if node is None or node.tag != tag:
        _bad("expected " + what)
    return node


def _seq(node, what="a SEQUENCE"):
    return _kids(_expect(node, 0x30, what))


def _at(items, index):
    return items[index] if 0 <= index < len(items) else None


def _oid(node):
    value = _expect(node, 0x06, "an OBJECT IDENTIFIER").value
    if not value or value[-1] & 0x80:
        _bad("malformed OBJECT IDENTIFIER")
    arcs, n = [], 0
    for index, byte in enumerate(value):
        if n == 0 and byte == 0x80:
            _bad("malformed OBJECT IDENTIFIER")
        n = (n << 7) | (byte & 0x7F)
        if n >= 1 << 64:
            _bad("OBJECT IDENTIFIER arc too large")
        if not byte & 0x80:
            arcs.append(n)
            n = 0
    first = arcs[0] // 40 if arcs[0] < 80 else 2
    return ".".join(str(arc) for arc in [first, arcs[0] - first * 40] + arcs[1:])


def _integer(node):
    value = _expect(node, 0x02, "an INTEGER").value
    if not value or (len(value) > 1 and ((value[0] == 0 and not value[1] & 0x80) or (value[0] == 0xFF and value[1] & 0x80))):
        _bad("malformed INTEGER")
    return value


def _octets(node):
    return _expect(node, 0x04, "an OCTET STRING").value


def _bit_string(node):
    value = _expect(node, 0x03, "a BIT STRING").value
    if not value or value[0] != 0:
        _bad("BIT STRING with unused bits")
    return value[1:]


UTC_TIME = re.compile(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z\Z", re.ASCII)
GENERALIZED_TIME = re.compile(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d*[1-9]))?Z\Z", re.ASCII)


def _time(node):
    """UTCTime or GeneralizedTime as an ISO string with milliseconds; a fraction is cut to three digits, never rounded."""
    text = node.value.decode("latin-1")
    match = UTC_TIME.match(text) if node.tag == 0x17 else GENERALIZED_TIME.match(text) if node.tag == 0x18 else None
    if not match:
        _bad("malformed time")
    parts = list(match.groups())
    if node.tag == 0x17:
        parts[0] = ("20" if int(parts[0]) < 50 else "19") + parts[0]
        parts.append(None)
    if int(parts[0]) < 1950:
        _bad("malformed time")
    fraction = ((parts[6] or "") + "000")[:3]
    try:
        datetime(int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5]))
    except ValueError:
        _bad("malformed time")
    return "%s-%s-%sT%s:%s:%s.%sZ" % (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], fraction)


OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
HASH_OIDS = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
SIGNATURE_OIDS = {"1.2.840.113549.1.1.11": ("rsa", "sha256"), "1.2.840.113549.1.1.12": ("rsa", "sha384"),
                  "1.2.840.113549.1.1.13": ("rsa", "sha512"), "1.2.840.10045.4.3.2": ("ec", "sha256"),
                  "1.2.840.10045.4.3.3": ("ec", "sha384"), "1.2.840.10045.4.3.4": ("ec", "sha512")}
# PKCS #1 v1.5 DigestInfo prefixes (RFC 8017 section 9.2, note 1).
DIGEST_INFO = {"sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
               "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
               "sha512": bytes.fromhex("3051300d060960864801650304020305000440")}
# NIST P-256 and P-384 (FIPS 186-4 D.1.2.3 and D.1.2.4): p, b, Gx, Gy, n; a = -3.
CURVES = {
    "1.2.840.10045.3.1.7": (
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    "1.3.132.0.34": (
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973),
}


def _algorithm(node):
    parts = _seq(node, "an AlgorithmIdentifier")
    if not parts or len(parts) > 2 or (len(parts) == 2 and (parts[1].tag != 0x05 or parts[1].value)):
        _bad("unexpected algorithm parameters")
    return _oid(parts[0])


def _hash_name(node):
    name = HASH_OIDS.get(_algorithm(node))
    if name is None:
        _bad("unsupported digest algorithm")
    return name


def _digest(name, data):
    return hashlib.new(name, data).digest()


def _on_curve(curve, x, y):
    p, b = curve[0], curve[1]
    return 0 <= x < p and 0 <= y < p and (y * y - (x * x * x - 3 * x + b)) % p == 0


def _ec_double(curve, point):
    p = curve[0]
    if point is None or point[1] == 0:
        return None
    x, y, z = point
    delta, gamma = z * z % p, y * y % p
    beta, alpha = x * gamma % p, 3 * (x - delta) * (x + delta) % p
    x3 = (alpha * alpha - 8 * beta) % p
    z3 = ((y + z) * (y + z) - gamma - delta) % p
    return (x3, (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p, z3)


def _ec_add(curve, a, b):
    p = curve[0]
    if a is None:
        return b
    if b is None:
        return a
    z1z1, z2z2 = a[2] * a[2] % p, b[2] * b[2] % p
    u1, u2 = a[0] * z2z2 % p, b[0] * z1z1 % p
    s1, s2 = a[1] * b[2] * z2z2 % p, b[1] * a[2] * z1z1 % p
    if u1 == u2:
        return _ec_double(curve, a) if s1 == s2 else None
    h, r = (u2 - u1) % p, (s2 - s1) % p
    hh = h * h % p
    hhh, v = h * hh % p, u1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    return (x3, (r * (v - x3) - s1 * hhh) % p, h * a[2] * b[2] % p)


def _ec_mul(curve, scalar, point):
    result = None
    for bit in bin(scalar)[2:]:
        result = _ec_double(curve, result)
        if bit == "1":
            result = _ec_add(curve, result, point)
    return result


def _ecdsa_verify(curve, public, hash_name, message, signature):
    p, n = curve[0], curve[4]
    try:
        parts = _seq(_der(signature), "an ECDSA signature")
        if len(parts) != 2:
            return False
        r, s = (int.from_bytes(_integer(part), "big", signed=True) for part in parts)
    except Rejected:
        return False
    if not (0 < r < n and 0 < s < n):
        return False
    digest = _digest(hash_name, message)
    e = int.from_bytes(digest, "big")
    if len(digest) * 8 > n.bit_length():
        e >>= len(digest) * 8 - n.bit_length()
    w = pow(s, n - 2, n)
    point = _ec_add(curve, _ec_mul(curve, e * w % n, (curve[2], curve[3], 1)), _ec_mul(curve, r * w % n, (public[0], public[1], 1)))
    if point is None or point[2] == 0:
        return False
    zinv = pow(point[2], p - 2, p)
    return (point[0] * zinv * zinv % p) % n == r


def _rsa_verify(public, hash_name, message, signature):
    modulus, exponent = public
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        return False
    info = DIGEST_INFO[hash_name] + _digest(hash_name, message)
    if size < len(info) + 11:
        return False
    return pow(value, exponent, modulus).to_bytes(size, "big") == b"\x00\x01" + b"\xff" * (size - len(info) - 3) + b"\x00" + info


def _public_key(spki):
    """('rsa', (n, e)) for an RSA key of at least 2048 bits, ('ec', (curve, point)) on P-256 or P-384."""
    parts = _seq(spki, "a SubjectPublicKeyInfo")
    if len(parts) != 2:
        _bad("malformed public key")
    alg = _seq(parts[0], "an AlgorithmIdentifier")
    kind, key = _oid(_at(alg, 0)), _bit_string(parts[1])
    if kind == OID_RSA and len(alg) == 2 and alg[1].tag == 0x05 and not alg[1].value:
        numbers = _seq(_der(key), "an RSA public key")
        if len(numbers) != 2:
            _bad("malformed RSA key")
        modulus, exponent = (int.from_bytes(_integer(number), "big", signed=True) for number in numbers)
        if not 2048 <= modulus.bit_length() <= 16384 or exponent < 3 or exponent.bit_length() > 64 or exponent % 2 == 0:
            _bad("unsupported RSA key")
        return ("rsa", (modulus, exponent))
    if kind == OID_EC_PUBLIC_KEY and len(alg) == 2:
        curve = CURVES.get(_oid(alg[1]))
        size = curve and (curve[0].bit_length() + 7) // 8
        if curve is None or len(key) != 1 + 2 * size or key[0] != 4:
            _bad("unsupported EC key")
        x, y = int.from_bytes(key[1:1 + size], "big"), int.from_bytes(key[1 + size:], "big")
        if not _on_curve(curve, x, y):
            _bad("EC key not on its curve")
        return ("ec", (curve, (x, y)))
    _bad("unsupported public key")


def _signature_ok(public, algorithm, message, signature):
    kind, hash_name = algorithm
    if public[0] != kind:
        return False
    if kind == "rsa":
        return _rsa_verify(public[1], hash_name, message, signature)
    return _ecdsa_verify(public[1][0], public[1][1], hash_name, message, signature)


def _certificate(data):
    """An X.509 certificate, read as far as the timestamp checks need."""
    parts = _seq(_der(data), "a certificate")
    if len(parts) != 3:
        _bad("malformed certificate")
    tbs_node, alg_node, sig_node = parts
    tbs = _seq(tbs_node, "a TBSCertificate")
    first = 1 if tbs and tbs[0].tag == 0xA0 else 0
    if len(tbs) < first + 6:
        _bad("malformed certificate")
    serial, inner_alg, issuer, validity, subject, spki = tbs[first:first + 6]
    algorithm = _algorithm(alg_node)
    if _algorithm(inner_alg) != algorithm:
        _bad("certificate signature algorithms differ")
    times = _seq(validity, "a Validity")
    if len(times) != 2:
        _bad("malformed validity")
    _expect(issuer, 0x30, "a Name")
    _expect(subject, 0x30, "a Name")
    extensions = {}
    for node in tbs[first + 6:]:
        if node.tag != 0xA3:
            continue
        holder = _kids(node)
        if len(holder) != 1:
            _bad("malformed extensions")
        for extension in _seq(holder[0]):
            items = _seq(extension)
            if len(items) < 2 or len(items) > 3:
                _bad("malformed extension")
            name = _oid(items[0])
            critical = len(items) == 3 and _expect(items[1], 0x01, "a BOOLEAN").value == b"\xff"
            if name in extensions:
                _bad("malformed extension")
            extensions[name] = (critical, _octets(items[-1]))
    return {"der": bytes(data), "tbs": tbs_node.raw, "algorithm": algorithm, "signature": _bit_string(sig_node),
            "serial": _integer(serial), "issuer": issuer.raw, "subject": subject.raw, "notBefore": _time(times[0]),
            "notAfter": _time(times[1]), "extensions": extensions, "spki": _expect(spki, 0x30, "a SubjectPublicKeyInfo")}


def _key_of(cert):
    """Read only for the signer and the roots: other certificates in a token are not signed over and may hold any key."""
    if "publicKey" not in cert:
        cert["publicKey"] = _public_key(cert["spki"])
    return cert["publicKey"]


def _within(cert, moment):
    return cert["notBefore"] <= moment <= cert["notAfter"]


def _issued_by(cert, root):
    algorithm = SIGNATURE_OIDS.get(cert["algorithm"])
    return (cert["issuer"] == root["subject"] and algorithm is not None
            and _signature_ok(_key_of(root), algorithm, cert["tbs"], cert["signature"]))


def certificate_from_pem(text):
    lines = re.split(r"\r?\n", text.strip(" \t\r\n")) if isinstance(text, str) else []
    if (len(lines) < 3 or lines[0] != "-----BEGIN CERTIFICATE-----" or lines[-1] != "-----END CERTIFICATE-----"
            or not all(re.match(r"[A-Za-z0-9+/=]+\Z", line, re.ASCII) for line in lines[1:-1])):
        return None
    body = "".join(lines[1:-1])
    try:
        data = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if base64.b64encode(data).decode("ascii") == body else None


def verify_timestamp(token, digest, authorities):
    """An RFC 3161 TimeStampResp, checked in verify-countersign.mjs verifyTimestamp's order. Returns tsa, genTime,
    serialNumber, policy and the offset of the TSTInfo in the token."""
    if not isinstance(token, bytes) or len(token) > COUNTERSIGN_LIMITS["timestampBytes"]:
        _bad("not a timestamp response of at most 64 KiB")
    response = _seq(_der(token), "a TimeStampResp")
    if len(response) != 2:
        _bad("no timestamp token")
    code = _integer(_at(_seq(response[0], "a PKIStatusInfo"), 0))
    if len(code) != 1 or code[0] > 1:
        _bad("the TSA did not grant the request")
    content_info = _seq(response[1], "a ContentInfo")
    if len(content_info) != 2 or _oid(content_info[0]) != OID_SIGNED_DATA:
        _bad("not a SignedData token")
    held = _kids(_expect(content_info[1], 0xA0, "explicit content"))
    if len(held) != 1:
        _bad("malformed token")
    signed_data = _seq(held[0], "a SignedData")
    index, certs = 3, []
    if _at(signed_data, index) is not None and signed_data[index].tag == 0xA0:
        certs = [_certificate(node.raw) for node in _kids(signed_data[index])]
        index += 1
    if _at(signed_data, index) is not None and signed_data[index].tag == 0xA1:
        index += 1
    if index != len(signed_data) - 1:
        _bad("malformed SignedData")
    encap = _seq(signed_data[2], "an EncapsulatedContentInfo")
    if len(encap) != 2 or _oid(encap[0]) != OID_TST_INFO:
        _bad("the token does not hold a TSTInfo")
    held = _kids(_expect(encap[1], 0xA0, "explicit content"))
    if len(held) != 1:
        _bad("malformed token")
    e_content_node = held[0]
    e_content = _octets(e_content_node)
    signers = _kids(_expect(signed_data[index], 0x31, "a SET of signers"))
    if len(signers) != 1:
        _bad("exactly one signer is accepted")
    info = _seq(signers[0], "a SignerInfo")
    if len(info) < 6 or len(info) > 7 or info[3].tag != 0xA0:
        _bad("the signer has no signed attributes")
    sid, digest_alg, attrs_node, sig_alg, sig_node = info[1:6]
    sid_parts = _seq(sid, "issuer and serial number (a signer named by key id is not supported)")
    if len(sid_parts) != 2:
        _bad("malformed signer id")
    sid_issuer, sid_serial = _expect(sid_parts[0], 0x30, "a Name").raw, _integer(sid_parts[1])
    signer = next((cert for cert in certs if cert["issuer"] == sid_issuer and cert["serial"] == sid_serial), None)
    if signer is None:
        _bad("the token does not carry its signer's certificate")
    hash_name, attrs = _hash_name(digest_alg), {}
    for attr in _kids(attrs_node):
        parts = _seq(attr)
        name = _oid(_at(parts, 0))
        values = _kids(_expect(parts[1], 0x31, "a SET of values")) if len(parts) == 2 else []
        if len(values) != 1 or name in attrs:
            _bad("malformed signed attribute")
        attrs[name] = values[0]
    if OID_CONTENT_TYPE not in attrs or _oid(attrs[OID_CONTENT_TYPE]) != OID_TST_INFO:
        _bad("the signed content type is not TSTInfo")
    if OID_MESSAGE_DIGEST not in attrs or _octets(attrs[OID_MESSAGE_DIGEST]) != _digest(hash_name, e_content):
        _bad("the signed digest does not match the TSTInfo")
    v2, v1 = attrs.get(OID_SIGNING_CERTIFICATE_V2), attrs.get(OID_SIGNING_CERTIFICATE)
    if v1 is None and v2 is None:
        _bad("no signing-certificate attribute")
    cert_id = _at(_seq(_at(_seq(v2 if v2 is not None else v1), 0)), 0)
    id_parts = _seq(cert_id)
    if v2 is not None and id_parts and id_parts[0].tag == 0x30:
        ess_hash = _hash_name(id_parts.pop(0))
    else:
        ess_hash = "sha256" if v2 is not None else "sha1"
    if _octets(_at(id_parts, 0)) != _digest(ess_hash, signer["der"]):
        _bad("the signing-certificate attribute names another certificate")
    sig_oid = _algorithm(sig_alg)
    algorithm = ("rsa", hash_name) if sig_oid == OID_RSA else SIGNATURE_OIDS.get(sig_oid)
    if algorithm is None:
        _bad("unsupported signature algorithm")
    if not _signature_ok(_key_of(signer), algorithm, b"\x31" + attrs_node.raw[1:], _octets(sig_node)):
        _bad("the token's signature does not verify")
    tst = _seq(_der(e_content), "a TSTInfo")
    version = _integer(_at(tst, 0))
    if version != b"\x01" or len(tst) < 5:
        _bad("malformed TSTInfo")
    policy, imprint, serial = _oid(tst[1]), _seq(tst[2], "a MessageImprint"), _integer(tst[3]).hex()
    gen_time = _time(_expect(tst[4], 0x18, "a GeneralizedTime"))
    eku = signer["extensions"].get(OID_EXT_KEY_USAGE)
    purposes = _seq(_der(eku[1])) if eku is not None and eku[0] else None
    if not purposes or len(purposes) != 1 or _oid(purposes[0]) != OID_TIME_STAMPING:
        _bad("the signer's certificate is not marked for time stamping only")
    if not _within(signer, gen_time):
        _bad("the signer's certificate was not valid at the stamped time")
    authority = next((a for a in authorities if _within(a["root"], gen_time) and _issued_by(signer, a["root"])), None)
    if authority is None:
        raise Rejected("timestamp-untrusted", "no TSA root in the key set issued this token")
    if len(imprint) != 2 or _hash_name(imprint[0]) != "sha256" or _octets(imprint[1]).hex() != digest:
        raise Rejected("timestamp-imprint-mismatch", "the token stamps another digest")
    return {"tsa": authority["name"], "genTime": gen_time, "serialNumber": serial, "policy": policy,
            "eContentOffset": e_content_node.body}


def read_keyset(text):
    """ScopeHaven's published key set (scopehaven-keys/1). It is the trust root, so it is never read loosely."""
    def invalid(detail):
        raise Rejected("keyset-invalid", detail)
    try:
        keyset = _json(text)
    except (ValueError, UnicodeDecodeError, RecursionError):
        invalid("not JSON")
    policy = keyset.get("policy") if isinstance(keyset, dict) else None
    if (not _exact_keys(keyset, ("schema", "publisher", "url", "updated", "countersigningKeys", "timestampAuthorities", "policy"))
            or keyset["schema"] != KEYSET_SCHEMA or keyset["publisher"] != COUNTERSIGNER["name"] or keyset["url"] != KEYSET_URL
            or not _iso_time(keyset["updated"]) or not _exact_keys(policy, ("rotation", "revocation"))
            or not isinstance(policy["rotation"], str) or not isinstance(policy["revocation"], str)
            or not isinstance(keyset["countersigningKeys"], list) or not isinstance(keyset["timestampAuthorities"], list)):
        invalid("not a scopehaven-keys/1 document")
    keys = {}
    for entry in keyset["countersigningKeys"]:
        if (not _exact_keys(entry, ("keyid", "publicKey", "status", "notBefore", "notAfter", "revokedAt", "note"))
                or not isinstance(entry["keyid"], str) or not HEX64.match(entry["keyid"]) or entry["keyid"] in keys
                or not _one_of(entry["status"], KEY_STATUSES) or not _iso_time(entry["notBefore"]) or not isinstance(entry["note"], str)
                or not all(value is None or _iso_time(value) for value in (entry["notAfter"], entry["revokedAt"]))
                or (entry["status"] == "revoked") != (entry["revokedAt"] is not None)):
            invalid("malformed countersigning key")
        try:
            public, keyid = public_key_from_pem(entry["publicKey"]) if isinstance(entry["publicKey"], str) else (None, None)
        except (ValueError, binascii.Error):
            public, keyid = None, None
        if public is None:
            invalid("key %s is not an Ed25519 public key" % entry["keyid"])
        if keyid != entry["keyid"]:
            invalid("key %s is not the SHA-256 of its public key" % entry["keyid"])
        keys[keyid] = dict(entry, key=public)
    authorities = []
    for entry in keyset["timestampAuthorities"]:
        if (not _exact_keys(entry, ("name", "url", "rootSha256", "rootCertificate")) or not isinstance(entry["name"], str)
                or not isinstance(entry["url"], str) or not isinstance(entry["rootSha256"], str) or not HEX64.match(entry["rootSha256"])):
            invalid("malformed timestamp authority")
        data = certificate_from_pem(entry["rootCertificate"])
        if data is None or _sha256(data) != entry["rootSha256"]:
            invalid("the %s root is not the certificate its sha256 names" % entry["name"])
        try:
            root = _certificate(data)
            _key_of(root)
        except Rejected:
            invalid("the %s root is not a certificate" % entry["name"])
        authorities.append({"name": entry["name"], "url": entry["url"], "root": root})
    return {"keys": keys, "authorities": authorities}


def _key_valid_at(entry, gen_time):
    """A signature stamped before a key was revoked stays valid; one stamped after does not."""
    if entry["revokedAt"] is not None and gen_time >= entry["revokedAt"]:
        raise Rejected("countersign-key-revoked", "key %s was revoked at %s" % (entry["keyid"], entry["revokedAt"]))
    if gen_time < entry["notBefore"] or (entry["notAfter"] is not None and gen_time >= entry["notAfter"]):
        raise Rejected("countersign-key-not-valid", "key %s was not in use at %s" % (entry["keyid"], gen_time))


def first_signature(envelope):
    """The first envelope's statement and signature, read without trust: the caller verified it already."""
    env = _json(envelope)
    entry = env["signatures"][0]
    return {"payloadType": env["payloadType"], "payload": base64.b64decode(env["payload"]), "keyid": entry["keyid"],
            "sig": base64.b64decode(entry["sig"])}


def _countersign_envelope(data, keys):
    if len(data) > COUNTERSIGN_LIMITS["envelopeBytes"]:
        raise Rejected("countersign-shape", "envelope size")
    try:
        env = _json(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Rejected("countersign-shape", "not JSON")
    if (not _exact_keys(env, ("payload", "payloadType", "signatures")) or env["payloadType"] != PAYLOAD_TYPE
            or not isinstance(env["signatures"], list) or len(env["signatures"]) != 1):
        raise Rejected("countersign-shape", "not a DSSE envelope with one signature")
    entry = env["signatures"][0]
    if not _exact_keys(entry, ("keyid", "sig")) or not isinstance(entry["keyid"], str):
        raise Rejected("countersign-shape", "signature")
    try:
        payload, sig = _strict_base64(env["payload"], "payload"), _strict_base64(entry["sig"], "sig")
    except Rejected:
        raise Rejected("countersign-shape", "base64")
    if entry["keyid"] not in keys:
        raise Rejected("countersign-key-unknown", "signed by a key that is not in ScopeHaven's published key set")
    return {"type": env["payloadType"], "payload": payload, "sig": sig, "key": keys[entry["keyid"]]}


def _parse_countersign_statement(payload):
    def shape(detail):
        raise Rejected("countersign-shape", detail)
    try:
        statement = _json(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        shape("payload is not JSON")
    try:
        canonical = _canonical_json(statement)
    except (RecursionError, UnicodeEncodeError):
        canonical = None
    if canonical != payload:
        shape("payload is not canonical")
    if (not _exact_keys(statement, ("_type", "subject", "predicateType", "predicate")) or statement["_type"] != STATEMENT_TYPE
            or statement["predicateType"] != COUNTERSIGN_PREDICATE):
        shape("not a countersignature statement")
    subject, predicate = statement["subject"], statement["predicate"]
    if (not isinstance(subject, list) or len(subject) != 1 or not _exact_keys(subject[0], ("name", "digest"))
            or subject[0]["name"] != STATEMENT_SUBJECT or not _exact_keys(subject[0]["digest"], ("sha256",))
            or not isinstance(subject[0]["digest"]["sha256"], str) or not HEX64.match(subject[0]["digest"]["sha256"])):
        shape("subject")
    if (not _exact_keys(predicate, ("meaning", "clock", "countersigner", "firstSignature", "request", "signedAt"))
            or predicate["meaning"] != COUNTERSIGN_MEANING or predicate["clock"] != COUNTERSIGN_CLOCK
            or not _exact_keys(predicate["countersigner"], ("name", "keys"))
            or predicate["countersigner"]["name"] != COUNTERSIGNER["name"] or predicate["countersigner"]["keys"] != COUNTERSIGNER["keys"]
            or not _iso_time(predicate["signedAt"])):
        shape("predicate")
    first, request = predicate["firstSignature"], predicate["request"]
    if (not _exact_keys(first, ("keyid", "sigSha256", "payloadType")) or not all(isinstance(first[k], str) and HEX64.match(first[k]) for k in ("keyid", "sigSha256"))
            or first["payloadType"] != PAYLOAD_TYPE):
        shape("firstSignature")
    if (not _exact_keys(request, ("licenceId", "release", "nonce")) or not isinstance(request["licenceId"], str)
            or not LICENCE_ID.match(request["licenceId"]) or not isinstance(request["release"], str) or not VERSION.match(request["release"])
            or not isinstance(request["nonce"], str) or not HEX32.match(request["nonce"])):
        shape("request")
    return statement


def _bind(statement, first):
    if statement["subject"][0]["digest"]["sha256"] != _sha256(first["payload"]):
        raise Rejected("countersign-subject-mismatch", "the countersignature is over another evidence statement")
    named = statement["predicate"]["firstSignature"]
    if named["keyid"] != first["keyid"] or named["sigSha256"] != _sha256(first["sig"]) or named["payloadType"] != first["payloadType"]:
        raise Rejected("countersign-signer-mismatch", "the countersignature names another first signature")


def _seconds(moment):
    return (datetime.strptime(moment, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()


def _examine_countersign(inputs, check_signature):
    cs = _countersign_envelope(inputs["countersignature"], inputs["keyset"]["keys"])
    if len(cs["sig"]) != 64 or not check_signature(cs["key"]["key"], pae(cs["type"], cs["payload"]), cs["sig"]):
        raise Rejected("countersign-signature-invalid")
    statement = _parse_countersign_statement(cs["payload"])
    _bind(statement, inputs["first"])
    stamp = verify_timestamp(inputs["timestamp"], _sha256(cs["sig"]), inputs["keyset"]["authorities"])
    _key_valid_at(cs["key"], stamp["genTime"])
    if _seconds(statement["predicate"]["signedAt"]) > _seconds(stamp["genTime"]) + CLOCK_SKEW_SECONDS:
        raise Rejected("countersign-time-inconsistent", "the countersigner's clock is ahead of the TSA's by more than five minutes")
    return {"cs": cs, "statement": statement, "stamp": stamp}


def _countersign_controls(checked, inputs, check_signature):
    cs, statement, stamp = checked["cs"], checked["statement"], checked["stamp"]
    first, keyset, token = inputs["first"], inputs["keyset"], inputs["timestamp"]

    def passes(attempt):
        try:
            attempt()
            return True
        except Rejected:
            return False

    unpublished = _json(inputs["countersignature"])
    unpublished["signatures"][0]["keyid"] = _sha256(SPKI_ED25519 + ed25519_public(os.urandom(32)))
    unpublished = json.dumps(unpublished).encode("utf-8")
    tampered = bytearray(token)
    tampered[stamp["eContentOffset"] + 4] ^= 1
    tampered = bytes(tampered)
    controls = [
        ("countersign-payload-tampered", lambda: check_signature(cs["key"]["key"], pae(cs["type"], _flip(cs["payload"])), cs["sig"])),
        ("countersign-signature-tampered", lambda: check_signature(cs["key"]["key"], pae(cs["type"], cs["payload"]), _flip(cs["sig"]))),
        ("countersign-unpublished-key", lambda: passes(lambda: _countersign_envelope(unpublished, keyset["keys"]))),
        ("countersign-other-statement", lambda: passes(lambda: _bind(statement, dict(first, payload=_flip(first["payload"]))))),
        ("countersign-other-first-signature", lambda: passes(lambda: _bind(statement, dict(first, sig=_flip(first["sig"]))))),
        ("timestamp-other-signature", lambda: passes(lambda: verify_timestamp(token, _sha256(_flip(cs["sig"])), keyset["authorities"]))),
        ("timestamp-token-tampered", lambda: passes(lambda: verify_timestamp(tampered, _sha256(cs["sig"]), keyset["authorities"]))),
        ("timestamp-untrusted-root", lambda: passes(lambda: verify_timestamp(token, _sha256(cs["sig"]), []))),
        ("countersign-key-revoked", lambda: passes(lambda: _key_valid_at(dict(cs["key"], revokedAt=stamp["genTime"]), stamp["genTime"]))),
    ]
    results = []
    for name, attempt in controls:
        try:
            accepted = attempt() is True
        except Rejected:
            accepted = False
        results.append({"id": name, "expected": "rejected", "observed": "accepted" if accepted else "rejected"})
    return results


def verify_countersignature(envelope, countersignature, timestamp, keyset, check_signature=None):
    """envelope: the first (operator) envelope, already verified by verify_envelope. countersignature and timestamp are
    the bytes of NAME.countersign.dsse.json and NAME.countersign.tsr (None when absent); keyset is the key set's bytes."""
    check_signature = check_signature or ed25519_verify
    try:
        if countersignature is None:
            raise Rejected("countersign-missing", "no countersignature was given")
        if timestamp is None:
            raise Rejected("timestamp-missing", "no timestamp token was given")
        inputs = {"countersignature": countersignature, "timestamp": timestamp, "first": first_signature(envelope),
                  "keyset": read_keyset(keyset)}
        checked = _examine_countersign(inputs, check_signature)
    except Rejected as error:
        return {"countersign": COUNTERSIGN_VERSION, "verified": False, "verdict": "rejected", "reason": error.reason,
                "detail": str(error), "selfChecks": []}
    self_checks = _countersign_controls(checked, inputs, check_signature)
    failed = [check["id"] for check in self_checks if check["observed"] != check["expected"]]
    cs, statement, stamp = checked["cs"], checked["statement"], checked["stamp"]
    predicate = statement["predicate"]
    return {"countersign": COUNTERSIGN_VERSION, "verified": not failed, "verdict": "self-check-failed" if failed else "verified",
            "reason": "negative-control-accepted" if failed else None,
            "detail": "This verifier accepted tampered input (%s); do not rely on it." % ", ".join(failed) if failed else None,
            "keyid": cs["key"]["keyid"], "keyStatus": cs["key"]["status"], "meaning": predicate["meaning"],
            "statementSha256": statement["subject"][0]["digest"]["sha256"], "firstSignerKeyid": predicate["firstSignature"]["keyid"],
            "request": predicate["request"], "signedAt": predicate["signedAt"], "clock": predicate["clock"],
            "timestamp": {"tsa": stamp["tsa"], "genTime": stamp["genTime"], "serialNumber": stamp["serialNumber"], "policy": stamp["policy"]},
            "selfChecks": self_checks}


def combined(first, countersignature):
    """Both must verify for the whole to verify."""
    if not first["verified"]:
        return dict(first, countersignature=None)
    if countersignature["verified"]:
        return dict(first, countersignature=countersignature)
    return dict(first, verified=False, verdict=countersignature["verdict"], reason=countersignature["reason"],
                detail=countersignature["detail"], countersignature=countersignature)


def read_bounded(path, limit):
    # Non-blocking, so a FIFO is refused instead of waited on; never follows a symlink.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("%s must be a regular file of at most %d bytes." % (os.path.basename(path), limit))
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError("%s grew past %d bytes while being read." % (os.path.basename(path), limit))
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _printable(value):
    """The result as JSON.stringify would print it: a number beyond a double (1e400 in a run file) is null, never Infinity."""
    if isinstance(value, float) and (math.isinf(value) or math.isnan(value)):
        return None
    if isinstance(value, list):
        return [_printable(item) for item in value]
    if isinstance(value, dict):
        return dict((key, _printable(item)) for key, item in value.items())
    return value


USAGE = ("Usage: verify_envelope.py --key PUBLIC_KEY.pem --envelope ENVELOPE.json (--dir DIR | FILE...) "
         "[--scopehaven-keys KEYS.json --countersignature NAME.countersign.dsse.json --timestamp NAME.countersign.tsr]")
COUNTERSIGN_FLAGS = ("keyset", "countersignature", "timestamp")


def _read_optional(path, limit):
    """A countersignature or token file; a missing one is reported as rejected (countersign-missing), not a file error."""
    try:
        return read_bounded(path, limit)
    except FileNotFoundError:
        return None


def main(argv):
    options, paths, flags = {}, [], {"--key": "key", "--envelope": "envelope", "--dir": "dir", "--scopehaven-keys": "keyset",
                                     "--countersignature": "countersignature", "--timestamp": "timestamp"}
    try:
        index = 0
        while index < len(argv):
            arg = argv[index]
            if not arg.startswith("--"):
                paths.append(arg)
                index += 1
                continue
            key = flags.get(arg)
            value = argv[index + 1] if index + 1 < len(argv) else None
            if not key or key in options or value is None or value.startswith("--"):
                raise ValueError(USAGE)
            options[key] = value
            index += 2
        if "key" not in options or "envelope" not in options or (bool(paths) if "dir" in options else not paths):
            raise ValueError(USAGE)
        # The countersignature is checked only with all three: ScopeHaven's published key set and both files.
        if any(flag in options for flag in COUNTERSIGN_FLAGS) and not all(flag in options for flag in COUNTERSIGN_FLAGS):
            raise ValueError(USAGE)
        public_pem = read_bounded(options["key"], 16384).decode("utf-8")
        envelope = read_bounded(options["envelope"], LIMITS["envelopeBytes"] + 1)  # oversize is reported as envelope-size
        files = {}
        if "dir" in options:
            for name in subject_names(envelope):
                try:
                    files[name] = read_bounded(os.path.join(options["dir"], name), LIMITS["subjectBytes"])
                except FileNotFoundError:
                    pass
        else:
            for path in paths:
                name = os.path.basename(path)
                if name in files:
                    raise ValueError("Two files are named %s." % name)
                files[name] = read_bounded(path, LIMITS["subjectBytes"])
        result = verify_envelope(envelope, public_pem, files)
        if "keyset" in options:
            keyset = read_bounded(options["keyset"], COUNTERSIGN_LIMITS["keysetBytes"])
            countersignature = _read_optional(options["countersignature"], COUNTERSIGN_LIMITS["envelopeBytes"] + 1)
            token = _read_optional(options["timestamp"], COUNTERSIGN_LIMITS["timestampBytes"] + 1)
            if result["verified"]:
                result = combined(result, verify_countersignature(envelope, countersignature, token, keyset))
            else:
                result = combined(result, None)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2))
        return 2
    print(json.dumps(_printable(result), indent=2))  # ASCII-escaped, so any string in a run identity prints
    return {"verified": 0, "rejected": 1}.get(result["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
