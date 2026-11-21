"""Minimal style checker for the fictional SensorHub firmware.

Checks: no tab characters, lines at most 100 characters, header files have an
include guard. Exits 1 if any violation is found.
"""

import sys
from pathlib import Path


def check(root: Path) -> list[str]:
    problems = []
    for path in sorted(root.rglob("*.[ch]")):
        text = path.read_text(encoding="utf-8")
        for n, line in enumerate(text.splitlines(), 1):
            if "\t" in line:
                problems.append(f"{path}:{n}: tab character")
            if len(line) > 100:
                problems.append(f"{path}:{n}: line longer than 100 characters")
        if path.suffix == ".h" and "#ifndef" not in text:
            problems.append(f"{path}: missing include guard")
    return problems


if __name__ == "__main__":
    roots = [Path(a) for a in sys.argv[1:]] or [Path("firmware")]
    found = [p for r in roots for p in check(r)]
    for p in found:
        print(p)
    print(f"style check: {len(found)} problem(s)")
    sys.exit(1 if found else 0)
