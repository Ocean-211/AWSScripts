#!/usr/bin/env python3
"""
Regex-based scanner for credentials and sensitive identifiers in files listed in
an input text file (same input format as the TruffleHog script).

Detects:
  - AWS access key IDs (AKIA/ASIA/...), secret access keys, session tokens
  - AWS ARNs
  - Passwords, usernames, secrets, API keys / tokens (JS, JSON, Python, YAML,
    .env style assignments)
  - Bearer tokens, JWTs, Basic-auth headers, private key blocks,
    credentials embedded in URLs

Input list: plain paths (one per line) or the unzipped_paths.txt report
(only "FILE:" lines are used). Folders and missing paths are skipped.

Output: a JSON file grouped by profile (DRC01, DEV01, ...). The JSON is written
ONLY when something is found. Secret values are redacted unless --include-raw.

Usage:
  python3 pattern_scan.py -i unzipped_paths.txt -o pattern_findings.json
  python3 pattern_scan.py -i list.txt --profile-root /data/lambda --workers 8
  python3 pattern_scan.py -i list.txt --categories aws_access_key,password,arn
"""

import argparse
import bisect
import json
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

SKIP_LABELS = ("ZIP:", "EXTRACTED_TO:", "INVALID_ZIP:", "FAILED_ZIP:", "ERROR:")
FILE_LABEL = "FILE:"

DEFAULT_MAX_SIZE_MB = 25
SNIPPET_RADIUS = 60

# Values that are only references to a secret, not the secret itself.
PLACEHOLDER_VALUE = re.compile(
    r"^(\$\{.*\}|\{\{.*\}\}|<.*>|%.*%|\$[A-Za-z_]\w*|process\.env.*|os\.environ.*|"
    r"null|none|undefined|true|false|string|\*{3,}|x{4,}|\.{3,})$",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Patterns. Order matters: specific patterns first, so that a value already
# reported by a specific pattern is not reported again by a generic one.
# Each entry: (category, name, compiled_regex, value_group, key_group, redact)
# --------------------------------------------------------------------------
I = re.IGNORECASE
KEYSEP = r"""["']?\s*[:=]\s*["']"""          # key": "   key = '   key: "
KEYPFX = r"(?<![\w.\-])"                      # start of an identifier

PATTERNS = [
    (
        "aws_access_key",
        "AWS access key ID",
        re.compile(r"(?<![A-Z0-9])(?P<value>(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16})(?![A-Z0-9])"),
        "value", None, True,
    ),
    (
        "aws_secret_key",
        "AWS secret access key",
        re.compile(
            KEYPFX + r"(?P<key>[\w.\-]{0,30}?(?:aws_?secret(?:_?access)?_?key|secret_?access_?key|SecretAccessKey|secret_?key_?id)[\w.\-]{0,10}?)"
            + KEYSEP + r"(?P<value>[A-Za-z0-9/+=]{40})[\"']",
            I,
        ),
        "value", "key", True,
    ),
    (
        "aws_session_token",
        "AWS session token",
        re.compile(
            KEYPFX + r"(?P<key>[\w.\-]{0,30}?(?:aws_?session_?token|session_?token|x-amz-security-token|SecurityToken)[\w.\-]{0,10}?)"
            + KEYSEP + r"(?P<value>[A-Za-z0-9/+=_\-]{60,})[\"']",
            I,
        ),
        "value", "key", True,
    ),
    (
        "private_key",
        "Private key block",
        re.compile(r"(?P<value>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
        "value", None, False,
    ),
    (
        "jwt",
        "JSON Web Token",
        re.compile(r"(?<![\w\-])(?P<value>eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
        "value", None, True,
    ),
    (
        "bearer_token",
        "Bearer token",
        re.compile(r"\bBearer\s+(?P<value>[A-Za-z0-9\-._~+/]{20,}=*)"),
        "value", None, True,
    ),
    (
        "basic_auth",
        "Basic auth header",
        re.compile(r"\bBasic\s+(?P<value>[A-Za-z0-9+/]{16,}={0,2})"),
        "value", None, True,
    ),
    (
        "url_credentials",
        "Credentials embedded in URL",
        re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://(?P<key>[^\s:/@\"'<>]{1,64}):(?P<value>[^\s:/@\"'<>]{3,128})@[\w.\-]+"),
        "value", "key", True,
    ),
    (
        "arn",
        "AWS ARN",
        re.compile(r"(?P<value>arn:aws[a-z\-]*:[a-z0-9\-]+:[a-z0-9\-]*:\d{0,12}:[^\s\"'<>,;)}\]\\]+)"),
        "value", None, False,
    ),
    (
        "password",
        "Password",
        re.compile(
            KEYPFX + r"(?P<key>[\w.\-]{0,40}?(?:password|passwd|passphrase|pwd)[\w.\-]{0,20}?)"
            + KEYSEP + r"(?P<value>[^\"'\s\\]{3,200})[\"']",
            I,
        ),
        "value", "key", True,
    ),
    (
        "secret",
        "Secret / API key / token",
        re.compile(
            KEYPFX + r"(?P<key>[\w.\-]{0,40}?(?:secret|api_?key|apikey|access_?key|auth_?token|access_?token|refresh_?token|"
            r"client_?secret|private_?key|credential|token)[\w.\-]{0,20}?)"
            + KEYSEP + r"(?P<value>[^\"'\s\\]{8,300})[\"']",
            I,
        ),
        "value", "key", True,
    ),
    (
        "username",
        "Username",
        re.compile(
            KEYPFX + r"(?P<key>[\w.\-]{0,40}?(?:user_?name|user_?id|user|login|uname|uid))"
            + KEYSEP + r"(?P<value>[^\"'\s\\]{2,100})[\"']",
            I,
        ),
        "value", "key", False,
    ),
]

ALL_CATEGORIES = sorted({p[0] for p in PATTERNS})


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def redact(value):
    if len(value) <= 8:
        return value[:1] + "*" * (len(value) - 1)
    return value[:4] + "*" * min(len(value) - 6, 12) + value[-2:]


def read_files(list_file):
    files, folders, missing, seen = [], 0, 0, set()
    with open(list_file, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith(SKIP_LABELS):
                continue
            if line.startswith(FILE_LABEL):
                line = line[len(FILE_LABEL):].strip()
            path = Path(line).expanduser()
            if path.is_dir():
                folders += 1
                continue
            if not path.is_file():
                missing += 1
                continue
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(resolved)
    return files, folders, missing


def detect_profile(path, profile_root, profile_regex):
    if profile_root is not None:
        try:
            parts = path.relative_to(profile_root).parts
            if len(parts) > 1:
                return parts[0]
        except ValueError:
            pass
    for part in path.parts:
        if profile_regex.fullmatch(part):
            return part
    return "UNKNOWN"


def read_text(path, max_bytes):
    """Return file text, or None if the file is binary, too large or unreadable."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_file(path_str, categories, include_raw, max_bytes):
    """Scan one file. Returns (path_str, findings, note)."""
    path = Path(path_str)
    text = read_text(path, max_bytes)
    if text is None:
        return path_str, [], "skipped (binary, unreadable or larger than size limit)"

    newline_offsets = [m.start() for m in re.finditer("\n", text)]
    claimed = []          # (start, end) of values already reported
    findings = []

    for category, name, regex, value_group, key_group, do_redact in PATTERNS:
        if category not in categories:
            continue

        for match in regex.finditer(text):
            start, end = match.span(value_group)
            value = match.group(value_group)

            if PLACEHOLDER_VALUE.match(value):
                continue
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            claimed.append((start, end))

            line_no = bisect.bisect_left(newline_offsets, start) + 1
            line_start = (newline_offsets[line_no - 2] + 1) if line_no > 1 else 0
            line_end = newline_offsets[line_no - 1] if line_no - 1 < len(newline_offsets) else len(text)

            shown = value if (include_raw or not do_redact) else redact(value)

            # Snippet: a window around the match with the value masked.
            win_start = max(line_start, start - SNIPPET_RADIUS)
            win_end = min(line_end, end + SNIPPET_RADIUS)
            snippet = text[win_start:start] + shown + text[end:win_end]
            snippet = snippet.replace("\r", "").strip()

            finding = {
                "line": line_no,
                "category": category,
                "type": name,
                "key": match.group(key_group) if key_group else None,
                "value": shown,
                "snippet": snippet,
            }
            findings.append(finding)

    findings.sort(key=lambda f: (f["line"], f["category"]))
    return path_str, findings, None


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Pattern-scan listed files for credentials; write JSON only if something is found.")
    p.add_argument("-i", "--input", required=True, help="Text file containing paths")
    p.add_argument("-o", "--output", default="pattern_findings.json")
    p.add_argument("--profile-root", help="Folder whose first-level subfolders are the profiles")
    p.add_argument("--profile-regex", default=r"[A-Za-z]{2,}\d+",
                   help="Path component pattern that identifies a profile (default: letters+digits)")
    p.add_argument("--categories", default=",".join(ALL_CATEGORIES),
                   help="Comma-separated categories to scan. Available: " + ", ".join(ALL_CATEGORIES))
    p.add_argument("--extensions",
                   help="Only scan these extensions, e.g. .js,.json,.py (default: every text file)")
    p.add_argument("--max-size-mb", type=int, default=DEFAULT_MAX_SIZE_MB, help="Skip files larger than this")
    p.add_argument("--workers", type=int, default=4, help="Parallel worker processes")
    p.add_argument("--include-raw", action="store_true", help="Write full secret values instead of redacted ones")
    return p.parse_args()


def main():
    args = parse_args()

    categories = {c.strip() for c in args.categories.split(",") if c.strip()}
    unknown = categories - set(ALL_CATEGORIES)
    if unknown:
        sys.exit("Unknown categories: {}. Available: {}".format(", ".join(sorted(unknown)), ", ".join(ALL_CATEGORIES)))

    profile_root = Path(args.profile_root).expanduser().resolve() if args.profile_root else None
    profile_regex = re.compile(args.profile_regex)
    max_bytes = args.max_size_mb * 1024 * 1024

    files, folders_skipped, missing_skipped = read_files(args.input)

    ext_skipped = 0
    if args.extensions:
        wanted = {e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
                  for e in args.extensions.split(",") if e.strip()}
        kept = [f for f in files if f.suffix.lower() in wanted]
        ext_skipped = len(files) - len(kept)
        files = kept

    print("Files to scan        : {}".format(len(files)))
    print("Folders skipped      : {}".format(folders_skipped))
    print("Missing paths skipped: {}".format(missing_skipped))
    if args.extensions:
        print("Skipped by extension : {}".format(ext_skipped))

    results = {}
    notes = []

    with ProcessPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(scan_file, str(f), categories, args.include_raw, max_bytes): f
            for f in files
        }
        for done, future in enumerate(as_completed(futures), start=1):
            file_path = futures[future]
            try:
                _, findings, note = future.result()
            except Exception as error:  # keep scanning the remaining files
                notes.append((file_path, "scan error: {}".format(error)))
                continue

            if note:
                notes.append((file_path, note))
            if findings:
                profile = detect_profile(file_path, profile_root, profile_regex)
                results.setdefault(profile, []).append({"file": str(file_path), "findings": findings})
                print("[{}/{}] {} finding(s) ({}): {}".format(done, len(files), len(findings), profile, file_path))
            else:
                print("[{}/{}] clean: {}".format(done, len(files), file_path))

    for file_path, note in notes:
        print("NOTE: {} - {}".format(file_path, note), file=sys.stderr)

    total = sum(len(f["findings"]) for entries in results.values() for f in entries)
    if total == 0:
        print("\nNo matches - no JSON file written.")
        return

    report = {}
    for profile in sorted(results):
        entries = sorted(results[profile], key=lambda e: e["file"])
        counts = {}
        for entry in entries:
            for finding in entry["findings"]:
                counts[finding["category"]] = counts.get(finding["category"], 0) + 1
        report[profile] = {
            "total_findings": sum(counts.values()),
            "by_category": dict(sorted(counts.items())),
            "files": entries,
        }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    print("\n{} finding(s) in {} profile(s) written to: {}".format(total, len(report), Path(args.output).resolve()))


if __name__ == "__main__":
    main()
