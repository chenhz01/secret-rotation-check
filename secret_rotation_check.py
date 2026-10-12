#!/usr/bin/env python3
"""secret-rotation-check: rotation ledger + overdue alerts + integrity verification.

Ledger = JSONL of append-only rotation events:
    {"secret_id", "action": "create|rotate|retire", "rotated_at": "YYYY-MM-DD",
     "owner": "...", "prev_hash": "...", "hash": "..."}
hash = sha256(secret_id|action|rotated_at|owner|prev_hash) truncated to 16 hex.
Pure stdlib. Exit codes: 0 ok, 1 overdue/violations/broken chain, 2 input error.
"""
import argparse
import hashlib
import json
import sys
from datetime import date, datetime

SPEC_VERSION = "1.0.0"
GENESIS = "GENESIS"
ACTIONS = ("create", "rotate", "retire")


def event_hash(ev):
    payload = "|".join([ev["secret_id"], ev["action"], ev["rotated_at"],
                        ev.get("owner") or "", ev.get("prev_hash") or GENESIS])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def make_event(secret_id, action, rotated_at, owner, prev_hash=GENESIS):
    if action not in ACTIONS:
        raise ValueError("action must be one of %s" % ", ".join(ACTIONS))
    parse_date(rotated_at)
    ev = {"secret_id": secret_id, "action": action, "rotated_at": rotated_at,
          "owner": owner, "prev_hash": prev_hash, "hash": ""}
    ev["hash"] = event_hash(ev)
    return ev


def parse_date(text):
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        raise ValueError("invalid date %r (expected YYYY-MM-DD)" % text)


def load_ledger(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("line %d: invalid JSON (%s)" % (lineno, exc.msg))
            if not isinstance(ev, dict) or "secret_id" not in ev:
                raise ValueError("line %d: event must be an object with 'secret_id'" % lineno)
            events.append(ev)
    return events


def verify_chain(events):
    """Recompute the hash chain globally (append-order). Returns list of breaks."""
    breaks = []
    prev = GENESIS
    for i, ev in enumerate(events):
        if ev.get("prev_hash") != prev:
            breaks.append({"index": i, "secret_id": ev.get("secret_id"),
                           "code": "broken_link", "detail": "prev_hash does not match predecessor"})
            prev = ev.get("hash") or GENESIS
            continue
        if ev.get("hash") != event_hash(ev):
            breaks.append({"index": i, "secret_id": ev.get("secret_id"),
                           "code": "bad_hash", "detail": "recomputed hash mismatch"})
        prev = ev.get("hash") or GENESIS
    return breaks


def check_ledger(events, policy, as_of):
    """Return a report dict: overdue secrets, expiring soon, completeness violations."""
    try:
        as_of_d = parse_date(as_of)
    except ValueError as exc:
        raise ValueError("as_of: %s" % exc)
    if isinstance(policy, str):
        with open(policy, "r", encoding="utf-8") as f:
            policy = json.load(f)
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict or a path to a JSON policy file")
    default_max = policy.get("default_max_age_days", 90)
    per_secret = policy.get("secrets", {})
    by_secret = {}
    for i, ev in enumerate(events):
        by_secret.setdefault(ev.get("secret_id"), []).append((i, ev))

    overdue, expiring, violations = [], [], []
    for sid, evs in by_secret.items():
        state = None
        last_rotated = None
        for i, ev in evs:
            action = ev.get("action")
            if action not in ACTIONS:
                violations.append({"secret_id": sid, "index": i, "code": "bad_action",
                                   "detail": "unknown action %r" % action})
                continue
            try:
                d = parse_date(ev.get("rotated_at"))
            except ValueError as exc:
                violations.append({"secret_id": sid, "index": i, "code": "bad_date", "detail": str(exc)})
                continue
            if state == "retired":
                violations.append({"secret_id": sid, "index": i, "code": "after_retire",
                                   "detail": "event after retire"})
            if not ev.get("owner"):
                violations.append({"secret_id": sid, "index": i, "code": "missing_owner",
                                   "detail": "event has no named owner"})
            if action == "create" and state is not None:
                violations.append({"secret_id": sid, "index": i, "code": "double_create",
                                   "detail": "second create event"})
            if last_rotated and d < last_rotated:
                violations.append({"secret_id": sid, "index": i, "code": "out_of_order",
                                   "detail": "rotated_at goes backwards"})
            if action in ("create", "rotate"):
                last_rotated = d
                state = "active"
            elif action == "retire":
                state = "retired"
        if state == "active" and last_rotated:
            max_age = per_secret.get(sid, {}).get("max_age_days", default_max)
            age = (as_of_d - last_rotated).days
            entry = {"secret_id": sid, "age_days": age, "max_age_days": max_age,
                     "last_rotated": last_rotated.isoformat(), "owner": evs[-1][1].get("owner")}
            if age > max_age:
                overdue.append(entry)
            elif max_age > 0 and age >= 0.8 * max_age:
                expiring.append(entry)
    return {"spec_version": SPEC_VERSION, "as_of": as_of, "secrets_tracked": len(by_secret),
            "overdue": overdue, "expiring_soon": expiring, "violations": violations}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="secret-rotation-check",
                                 description="Secret rotation ledger: overdue alerts + integrity checks")
    sub = ap.add_subparsers(dest="cmd")
    pc = sub.add_parser("check", help="check ledger against policy")
    pc.add_argument("--ledger", required=True)
    pc.add_argument("--policy", required=True)
    pc.add_argument("--as-of", dest="as_of", required=True, help="YYYY-MM-DD")
    pv = sub.add_parser("verify", help="verify hash-chain integrity")
    pv.add_argument("--ledger", required=True)
    pe = sub.add_parser("add", help="append an event with computed hash")
    pe.add_argument("--ledger", required=True)
    pe.add_argument("--secret-id", required=True)
    pe.add_argument("--action", required=True, choices=ACTIONS)
    pe.add_argument("--at", required=True, help="YYYY-MM-DD")
    pe.add_argument("--owner", required=True)

    args = ap.parse_args(argv)
    if args.cmd is None:
        ap.print_help(sys.stderr)
        return 2
    try:
        if args.cmd == "check":
            events = load_ledger(args.ledger)
            with open(args.policy, "r", encoding="utf-8") as f:
                policy = json.load(f)
            report = check_ledger(events, policy, args.as_of)
            print(json.dumps({k: report[k] for k in ("as_of", "secrets_tracked")}))
            for section in ("overdue", "expiring_soon", "violations"):
                for item in report[section]:
                    print(section.upper(), json.dumps(item, ensure_ascii=False))
            return 1 if (report["overdue"] or report["violations"]) else 0
        if args.cmd == "verify":
            breaks = verify_chain(load_ledger(args.ledger))
            print("chain breaks: %d" % len(breaks))
            for b in breaks:
                print("BREAK", json.dumps(b))
            return 1 if breaks else 0
        if args.cmd == "add":
            events = load_ledger(args.ledger) if __import__("os").path.exists(args.ledger) else []
            prev = events[-1]["hash"] if events else GENESIS
            ev = make_event(args.secret_id, args.action, args.at, args.owner, prev)
            with open(args.ledger, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            print("appended %s %s hash=%s" % (ev["secret_id"], ev["action"], ev["hash"]))
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
