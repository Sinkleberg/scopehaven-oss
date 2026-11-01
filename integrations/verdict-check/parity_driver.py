#!/usr/bin/env python3
"""Test helper for verdict-check.test.mjs; auditors do not need it.

Loads verify_verdicts.py by path and exposes its internals to the Node tests:

    parity_driver.py evaluate CASES.json   grade [{kind, attempts}] with the checker's own evaluator
    parity_driver.py readers TEXTS.json    run the reply readers on each text
    parity_driver.py check FILE...         check each run file on its own, without the negative controls
    parity_driver.py constants             print the pinned rules, for the drift test
    parity_driver.py accept-all FILE...    run the pack with a checker that trusts every stored label
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("verify_verdicts", os.path.join(HERE, "verify_verdicts.py"))
vv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vv)


def evaluate(path):
    out = []
    # Read as the checker reads a run file, so numbers are JavaScript's.
    for case in vv.parse_json(open(path, "rb").read()):
        try:
            status, assertions = vv.evaluate_check(case["kind"], case["attempts"])
            out.append({"status": status, "assertions": [list(a) for a in assertions]})
        except vv.JSTypeError:
            out.append({"throws": True})
    return out


def readers(path):
    out = []
    for text in json.load(open(path, encoding="utf-8")):
        read = vv.read_promise_reply(text, {})
        out.append({"statesUnsupportedReason": vv.states_unsupported_reason(text), "claimsSuccess": vv.text_claims_success(text),
                    "reportsNotDone": vv.text_reports_not_done(text), "promise": read})
    return out


def check(paths):
    out = []
    for path in paths:
        name = os.path.basename(path)
        try:
            value = vv.parse_json(open(path, "rb").read())
            report = vv.analyze_value(name, value)
            out.append({"file": name, "accepted": True, "report": report})
        except vv.Rejected as error:
            out.append({"file": name, "accepted": False, "reason": error.reason, "detail": error.detail})
    return out


def constants():
    return {"suite": [list(row) for row in vv.SYNTHETIC_SUITE], "suiteHash": vv.SYNTHETIC_SUITE_HASH, "policy": vv.POLICY, "policyHash": vv.POLICY_HASH,
            "fixtureHash": vv.FIXTURE_HASH, "records": vv.RECORDS, "orders": vv.ORDERS, "subscriptions": vv.SUBSCRIPTIONS, "today": vv.FIXTURE_TODAY,
            "canaries": vv.CANARIES, "synthetic": vv.SYNTHETIC, "scenarioInputs": vv.SCENARIO_INPUTS, "prohibitionNames": vv.PROHIBITION_NAMES,
            "noteAssertions": vv.NOTE_ASSERTIONS, "storedNoteKeys": list(vv.STORED_NOTE_KEYS), "promiseLedger": vv.PROMISE_LEDGER,
            "conversation": vv.CONVERSATION, "conversationTransports": list(vv.CONVERSATION_TRANSPORTS),
            "conversationIdentityReasons": list(vv.CONVERSATION_IDENTITY_REASONS), "policyAssertion": vv.POLICY_ASSERTION, "scopeNote": vv.SCOPE_NOTE,
            "observerOutput": dict((k, {"source": s, "kind": kind}) for k, (s, kind) in vv.OBSERVER_OUTPUT.items()), "custodyBySource": vv.CUSTODY_BY_SOURCE,
            "sources": list(vv.SOURCES), "operations": list(vv.OPERATIONS), "outcomes": list(vv.OUTCOMES), "coverage": list(vv.COVERAGE),
            "presenceOnlySources": list(vv.PRESENCE_ONLY_SOURCES), "reportOnlySources": list(vv.REPORT_ONLY_SOURCES),
            "sequenceNative": vv.SEQUENCE_NATIVE, "refusalStatuses": list(vv.REFUSAL_STATUSES), "harnessError": vv.HARNESS_ERROR}


def accept_all(paths):
    # A broken checker: every synthetic row's stored label is taken as re-derived.
    original = vv.check_synthetic

    def check_synthetic(name, run):
        rows = run.get("results") or []
        report = vv.new_report(name, run, "synthetic-fixture", vv.SYNTHETIC_SUITE_LABEL)
        report["rederived"] = [{"id": r.get("id"), "status": r.get("status")} for r in rows]
        return vv.summarize(report)
    vv.check_synthetic = check_synthetic
    try:
        files = [(os.path.basename(p), open(p, "rb").read()) for p in paths]
        reports, others, controls = vv.check_pack(files)
        verdict, summary, detail = vv.overall(reports, others, controls)
    finally:
        vv.check_synthetic = original
    return {"verdict": verdict, "detail": detail, "selfChecks": controls}


if __name__ == "__main__":
    mode, args = sys.argv[1], sys.argv[2:]
    result = {"evaluate": lambda: evaluate(args[0]), "readers": lambda: readers(args[0]), "check": lambda: check(args),
              "constants": constants, "accept-all": lambda: accept_all(args)}[mode]()
    print(json.dumps(result))
