#!/usr/bin/env python3
"""Prove the timing regressions detect frozen-clock verification; CI only."""
from pathlib import Path
import re
import subprocess

FILES = ['src/observation.rs']
originals = {Path(name): Path(name).read_bytes() for name in FILES}
try:
    for path, original in originals.items():
        source = original.decode()
        for boundary in ("dispatch_at", "completed_at", "accepted_at"):
            old = f"let {boundary} = clock();"
            if source.count(old) != 1:
                raise SystemExit(f"timing control source drift: {path}: {boundary}")
            source = source.replace(old, f"let {boundary} = now;")
        path.write_text(source)
    result = subprocess.run(
        ["cargo", "test", "--locked", "--lib", "tests::timing::", "--", "--nocapture"],
        capture_output=True, text=True,
    )
    output = result.stdout + result.stderr
    # Compilation failures and empty selections are not regression evidence.
    if (result.returncode != 101 or "test result: FAILED" not in output
            or "assertion" not in output
            or "test tests::timing::" not in output
            or "error[E" in output):
        print(output)
        raise SystemExit("frozen-clock control did not produce a test assertion failure")
    expected = ['observer_rechecks_age_and_deadlines_after_async_reply_and_host_reservation']
    for name in expected:
        if not re.search(r"test tests::timing::" + re.escape(name) + r" \.\.\. FAILED", output):
            print(output)
            raise SystemExit(f"timing regression did not reject frozen clocks: {name}")
    print("Frozen-clock mutation rejected by timing regression assertions")
finally:
    for path, original in originals.items():
        path.write_bytes(original)
