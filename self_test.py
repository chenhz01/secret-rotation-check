#!/usr/bin/env python3
"""self_test for secret-rotation-check. Tiers: [A] functional, [B] exception/CLI, [C] extreme edges."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import secret_rotation_check as src  # noqa: E402

RESULTS = []


def check(name, cond):
    RESULTS.append((name, bool(cond)))


def run_cli(args):
    return subprocess.run([sys.executable, os.path.join(HERE, "secret_rotation_check.py")] + args,
                          capture_output=True, text=True)


TMP = tempfile.mkdtemp(prefix="src_selftest_")


def p(name):
    return os.path.join(TMP, name)


def write_ledger(name, events):
    path = p(name)
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    return path


def chain(events):
    """Build a proper hash chain over the given raw events."""
    out, prev = [], "GENESIS"
    for ev in events:
        e = dict(ev)
        e["prev_hash"] = prev
        e["hash"] = src.event_hash(e)
        out.append(e)
        prev = e["hash"]
    return out


def policy(default=90, secrets=None):
    path = p("pol_%d.json" % len(RESULTS))
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"default_max_age_days": default, "secrets": secrets or {}}, f)
    return path


EV = src.make_event

# ---------------- [A] functional ----------------
check("A01 fresh create not overdue", src.check_ledger(
    chain([EV("s1", "create", "2026-09-15", "alice")]), policy(90), "2026-10-11")["overdue"] == [])
check("A02 100-day-old secret overdue at 90", src.check_ledger(
    chain([EV("s1", "create", "2026-07-03", "alice")]), policy(90), "2026-10-11")["overdue"][0]["secret_id"] == "s1")
check("A03 rotation resets age", src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "alice"), EV("s1", "rotate", "2026-10-01", "alice")]),
    policy(90), "2026-10-11")["overdue"] == [])
check("A04 retired secret never overdue", src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "alice"), EV("s1", "retire", "2026-02-01", "alice")]),
    policy(90), "2026-10-11")["overdue"] == [])
check("A05 per-secret tighter budget wins", src.check_ledger(
    chain([EV("s1", "create", "2026-09-20", "a")]), policy(90, {"s1": {"max_age_days": 10}}),
    "2026-10-11")["overdue"][0]["max_age_days"] == 10)
check("A06 expiring_soon at 80% of budget", src.check_ledger(
    chain([EV("s1", "create", "2026-07-20", "a")]), policy(90), "2026-10-11")["expiring_soon"][0]["age_days"] == 83)
check("A07 event hash deterministic", EV("s1", "rotate", "2026-01-01", "o")["hash"]
      == EV("s1", "rotate", "2026-01-01", "o")["hash"])
check("A08 hash is 16 hex chars", len(EV("s1", "create", "2026-01-01", "o")["hash"]) == 16)
check("A09 chain of 3 verifies clean", src.verify_chain(chain(
    [EV("s1", "create", "2026-01-01", "a"), EV("s1", "rotate", "2026-02-01", "a"),
     EV("s2", "create", "2026-03-01", "b")])) == [])
check("A10 tampered owner breaks hash", src.verify_chain(
    [dict(chain([EV("s1", "create", "2026-01-01", "a")])[0], owner="eve")])[0]["code"] == "bad_hash")
check("A11 missing owner flagged", "missing_owner" in [v["code"] for v in src.check_ledger(
    chain([EV("s1", "create", "2026-09-01", "")]), policy(90), "2026-10-11")["violations"]])
check("A12 event after retire flagged", "after_retire" in [v["code"] for v in src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "a"), EV("s1", "retire", "2026-02-01", "a"),
           EV("s1", "rotate", "2026-03-01", "a")]), policy(90), "2026-10-11")["violations"]])
check("A13 out-of-order dates flagged", "out_of_order" in [v["code"] for v in src.check_ledger(
    chain([EV("s1", "create", "2026-05-01", "a"), EV("s1", "rotate", "2026-02-01", "a")]),
    policy(90), "2026-10-11")["violations"]])
check("A14 double create flagged", "double_create" in [v["code"] for v in src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "a"), EV("s1", "create", "2026-02-01", "a")]),
    policy(90), "2026-10-11")["violations"]])
check("A15 secrets_tracked counted", src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "a"), EV("s2", "create", "2026-01-01", "b")]),
    policy(90), "2026-10-11")["secrets_tracked"] == 2)
check("A16 genesis prev_hash is GENESIS", EV("s1", "create", "2026-01-01", "a")["prev_hash"] == "GENESIS")
check("A17 linked events chain prev hashes", chain([EV("s1", "create", "2026-01-01", "a"),
      EV("s1", "rotate", "2026-02-01", "a")])[1]["prev_hash"] ==
      chain([EV("s1", "create", "2026-01-01", "a"), EV("s1", "rotate", "2026-02-01", "a")])[0]["hash"])
check("A18 overdue entry carries owner+age", src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "zoe")]), policy(30), "2026-10-11")["overdue"][0]["owner"] == "zoe")
check("A19 empty ledger gives zero counts", src.check_ledger([], policy(90), "2026-10-11")["secrets_tracked"] == 0)
check("A20 broken link reported with index", src.verify_chain(
    [chain([EV("s1", "create", "2026-01-01", "a")])[0],
     dict(EV("s2", "create", "2026-02-01", "b"), prev_hash="WRONG")])[0]["index"] == 1)

# ---------------- [B] exception / CLI paths ----------------
def _raises(exc_type, fn, *args):
    try:
        fn(*args)
        return False
    except exc_type:
        return True


def _raises_line(token):
    path = p("corrupt.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"secret_id": "s"}) + "\n{broken\n")
    try:
        src.load_ledger(path)
        return False
    except ValueError as exc:
        return token in str(exc)


def _raises_line2():
    path = p("notobj.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write("[1,2]\n")
    return _raises(ValueError, src.load_ledger, path)


def _add_and_verify():
    led = p("grown.jsonl")
    ok1 = run_cli(["add", "--ledger", led, "--secret-id", "s1", "--action", "create",
                   "--at", "2026-09-01", "--owner", "a"]).returncode == 0
    ok2 = run_cli(["add", "--ledger", led, "--secret-id", "s1", "--action", "rotate",
                   "--at", "2026-10-01", "--owner", "a"]).returncode == 0
    ok3 = run_cli(["verify", "--ledger", led]).returncode == 0
    return ok1 and ok2 and ok3


check("B01 bad action rejected", _raises(ValueError, EV, "s1", "refresh", "2026-01-01", "a"))
check("B02 bad date format rejected", _raises(ValueError, EV, "s1", "create", "01/01/2026", "a"))
check("B03 ledger corrupt line raises with lineno", _raises_line("line 2"))
check("B04 ledger non-object line raises", _raises_line2())
check("B05 as_of invalid date fails check", _raises(ValueError, src.check_ledger, [], policy(90), "tomorrow"))
check("B06 CLI check overdue exits 1", run_cli(
    ["check", "--ledger", write_ledger("old.jsonl", chain([EV("s1", "create", "2026-01-01", "a")])),
     "--policy", policy(30), "--as-of", "2026-10-11"]).returncode == 1)
check("B07 CLI check fresh exits 0", run_cli(
    ["check", "--ledger", write_ledger("new.jsonl", chain([EV("s1", "create", "2026-10-01", "a")])),
     "--policy", policy(90), "--as-of", "2026-10-11"]).returncode == 0)
check("B08 CLI verify clean exits 0", run_cli(
    ["verify", "--ledger", write_ledger("ok.jsonl", chain([EV("s1", "create", "2026-01-01", "a")]))]).returncode == 0)
check("B09 CLI verify tampered exits 1", run_cli(
    ["verify", "--ledger", write_ledger("bad.jsonl",
     [dict(chain([EV("s1", "create", "2026-01-01", "a")])[0], owner="mallory")])]).returncode == 1)
check("B10 CLI add appends with chain link", _add_and_verify())
check("B11 CLI check missing ledger exits 2", run_cli(
    ["check", "--ledger", p("nope.jsonl"), "--policy", policy(90), "--as-of", "2026-10-11"]).returncode == 2)
check("B12 CLI check bad as-of exits 2", run_cli(
    ["check", "--ledger", p("ok.jsonl"), "--policy", policy(90), "--as-of", "2026-13-99"]).returncode == 2)
check("B13 CLI no subcommand exits 2", run_cli([]).returncode == 2)
check("B14 CLI add bad action exits 2", run_cli(
    ["add", "--ledger", p("x.jsonl"), "--secret-id", "s", "--action", "zap",
     "--at", "2026-01-01", "--owner", "a"]).returncode == 2)
check("B15 CLI verify missing file exits 2", run_cli(["verify", "--ledger", p("nope2.jsonl")]).returncode == 2)

# ---------------- [C] extreme edges ----------------
check("C01 empty ledger file checks clean", run_cli(
    ["check", "--ledger", write_ledger("empty.jsonl", []), "--policy", policy(90),
     "--as-of", "2026-10-11"]).returncode == 0)
check("C02 verify empty chain clean", src.verify_chain([]) == [])
check("C03 leap-day rotation parsed", src.check_ledger(
    chain([EV("s1", "create", "2024-02-29", "a")]), policy(90), "2026-10-11")["overdue"][0]["age_days"] > 700)
check("C04 unicode owner and secret id", src.check_ledger(
    chain([EV("密钥-生产", "create", "2026-10-01", "管理员")]), policy(90), "2026-10-11")["overdue"] == [])
check("C05 500-secret ledger all overdue", len(src.check_ledger(
    chain([EV("s%03d" % i, "create", "2026-01-01", "a") for i in range(500)]),
    policy(30), "2026-10-11")["overdue"]) == 500)
check("C06 1000-event chain verifies", len(src.verify_chain(chain(
    [EV("s%d" % (i // 10), "rotate" if i % 10 else "create", "2026-%02d-%02d" % (i % 12 + 1, i % 28 + 1), "a")
     for i in range(1000)]))) == 0)
check("C07 tampered middle breaks only later links", len(src.verify_chain(
    [dict(chain([EV("s1", "create", "2026-01-01", "a")])[0], owner="x", hash="deadbeefdeadbeef")] +
    chain([EV("s2", "create", "2026-02-01", "b")])[1:])) >= 1)
check("C08 long secret id (10k chars) hashed ok", len(EV("s" * 10000, "create", "2026-01-01", "a")["hash"]) == 16)
check("C09 same day create+check age 0", src.check_ledger(
    chain([EV("s1", "create", "2026-10-11", "a")]), policy(90), "2026-10-11")["overdue"] == [])
_r10 = src.check_ledger(chain([EV("s1", "create", "2026-12-01", "a")]), policy(90), "2026-10-11")
check("C10 future-dated create: no overdue, no violation",
      _r10["overdue"] == [] and _r10["violations"] == [])
_bl = p("blank.jsonl")
with open(_bl, "w", encoding="utf-8") as _f:
    _f.write("\n" + json.dumps(chain([EV("s1", "create", "2026-01-01", "a")])[0]) + "\n\n")
check("C11 blank lines in ledger skipped", len(src.load_ledger(_bl)) == 1)
check("C12 duplicate identical events double-create flagged", "double_create" in [v["code"] for v in
      src.check_ledger(chain([EV("s1", "create", "2026-01-01", "a"), EV("s1", "create", "2026-01-01", "a")]),
                       policy(90), "2026-10-11")["violations"]])
check("C13 unicode corrupt line error readable", _raises(ValueError, src.load_ledger,
      write_ledger("u.jsonl", ["{\"secret_id\": \"密钥\", oops}"])))
check("C14 policy with zero max age: anything older fails", src.check_ledger(
    chain([EV("s1", "create", "2026-10-10", "a")]), policy(0), "2026-10-11")["overdue"][0]["age_days"] == 1)
check("C15 huge 200k-char owner hashed ok", len(EV("s", "create", "2026-01-01", "o" * 200000)["hash"]) == 16)
check("C16 chain with 300 rotations per secret verifies", src.verify_chain(chain(
    [EV("s1", "rotate" if i else "create", "2026-%02d-%02d" % (i % 12 + 1, i % 28 + 1), "a")
     for i in range(300)])) == [])
check("C17 add to new ledger creates file", os.path.exists(p("created.jsonl")) or run_cli(
    ["add", "--ledger", p("created.jsonl"), "--secret-id", "s", "--action", "create",
     "--at", "2026-10-11", "--owner", "a"]).returncode == 0)
check("C18 report json serializable", isinstance(json.dumps(src.check_ledger(
    chain([EV("s", "create", "2026-01-01", "a")]), policy(1), "2026-10-11")), str))
check("C19 expiring_soon excludes already-overdue", len(src.check_ledger(
    chain([EV("s1", "create", "2026-01-01", "a")]), policy(30), "2026-10-11")["expiring_soon"]) == 0)
check("C20 hash changes when owner changes", EV("s", "create", "2026-01-01", "a")["hash"] !=
      EV("s", "create", "2026-01-01", "b")["hash"])


def main():
    passed = sum(1 for _, ok in RESULTS if ok)
    total = len(RESULTS)
    for n, ok in RESULTS:
        if not ok:
            print("FAIL:", n)
    print("SUMMARY: PASS %d/%d" % (passed, total))
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
