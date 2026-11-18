"""Check the regex entries in template.yaml against sample inputs.

Python's re is close enough to RE2 for these patterns (no lookaround or
backreference). Run: python3 test/test_patterns.py
"""
import base64
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

TEMPLATE = Path(__file__).resolve().parent.parent / "template.yaml"
ENTRY = re.compile(r"^\s+- '(?P<regex>\(\?:\^\|.*)'\s*$")


def load_patterns() -> list[re.Pattern[str]]:
    patterns = []
    for line in TEMPLATE.read_text(encoding="utf-8").splitlines():
        m = ENTRY.match(line)
        if m:
            patterns.append(re.compile(m.group("regex")))
    return patterns


def matches(patterns: list[re.Pattern[str]], value: str) -> bool:
    return any(p.search(value) for p in patterns)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    patterns = load_patterns()
    logger.info("loaded %d patterns", len(patterns))
    if len(patterns) != 4:
        logger.error("expected 4 patterns")
        return 1
    too_long = [p.pattern for p in patterns if len(p.pattern) > 200]
    if too_long:
        logger.error("pattern longer than 200 chars: %s", too_long)
        return 1

    a = "A"
    should_match = {
        "trigger 64A+=": a * 64 + "=",
        "trigger 128A+=": a * 128 + "=",
        "basic header, 64A+=": "Basic " + a * 64 + "=",
        "0 chars + ==": a * 32 + "==",
        "1 char + =": a * 33 + "=",
        "1 char + ===": a * 33 + "===",
        "2 chars + =": a * 34 + "=",
        "2 chars + ===": a * 34 + "===",
        "3 chars + ==": a * 35 + "==",
        "base64url chars": "-_" * 16 + "A=",
        "inside JSON": '{"t":"' + a * 64 + '="}',
        "query string": "x=" + a * 64 + "=&y=1",
        "cookie style": "session=" + a * 40 + "=",
    }
    should_not_match = {
        "valid padded 1": "Basic " + base64.b64encode(b"u" * 47 + b"p").decode(),
        "valid 2 pad": a * 34 + "==",
        "valid 1 pad": a * 35 + "=",
        "valid no pad": a * 36,
        "short malformed (<32)": a * 20 + "=",
        "short valid": "Basic dXNlcjpwYXNz",
        "jwt like": "eyJhbGciOiJIUzI1NiJ9." + "e" * 40 + "." + "s" * 43,
        "plain text": "hello world, this is a normal sentence = ok",
        "uuid": "123e4567-e89b-12d3-a456-426614174000",
        "equals inside key": "k=" + a * 31,
    }
    failed = 0
    for name, value in should_match.items():
        ok = matches(patterns, value)
        logger.info("%-26s expect match    -> %s", name, "OK" if ok else "FAIL")
        failed += 0 if ok else 1
    for name, value in should_not_match.items():
        ok = not matches(patterns, value)
        logger.info("%-26s expect no match -> %s", name, "OK" if ok else "FAIL")
        failed += 0 if ok else 1
    logger.info("failed=%d", failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
