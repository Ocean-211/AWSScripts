#!/usr/bin/env python3
"""
Scan the FILES listed in an input list with TruffleHog and write a JSON report
containing ONLY the files where TruffleHog identified stored secrets.

- Folders and non-existent paths in the list are skipped.
- Input list can be plain paths (one per line) or the unzipped_paths.txt report
  (only "FILE:" lines are used; ZIP:/EXTRACTED_TO:/INVALID_ZIP:/FAILED_ZIP:/ERROR:
  lines are ignored).
- Findings are grouped by profile (DRC01, DEV01, ...).
- If nothing is found, no JSON file is created.

Usage:
  python3 trufflehog_json_scan.py -i unzipped_paths.txt -o trufflehog_findings.json
  python3 trufflehog_json_scan.py -i list.txt --profile-root /data/lambda --no-verification
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SKIP_LABELS = ("ZIP:", "EXTRACTED_TO:", "INVALID_ZIP:", "FAILED_ZIP:", "ERROR:")
FILE_LABEL = "FILE:"


def read_files(list_file):
    """Return (files, folders_skipped, missing_skipped)."""
    files, folders, missing, seen = [], 0, 0, set()

    with open(list_file, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
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
    """Profile = first folder under --profile-root, else first path part matching the regex."""
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


def scan_file(trufflehog_bin, file_path, extra_args, timeout):
    """Run TruffleHog against one file. Returns (findings, error)."""
    command = [trufflehog_bin, "filesystem", str(file_path), "--json", "--no-update"]
    command.extend(extra_args)

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "timed out after {}s".format(timeout)
    except OSError as error:
        return [], "could not run TruffleHog: {}".format(error)

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" in record:
            findings.append(record)

    error = None
    if not findings and result.returncode not in (0, 183):
        error = "exit code {}: {}".format(result.returncode, result.stderr.strip()[-300:])

    return findings, error


def to_entry(scanned_file, record, include_raw):
    fs = record.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
    entry = {
        "file": fs.get("file", str(scanned_file)),
        "line": fs.get("line"),
        "detector": record.get("DetectorName"),
        "decoder": record.get("DecoderName"),
        "verified": record.get("Verified", False),
        "redacted": record.get("Redacted"),
        "extra_data": record.get("ExtraData"),
    }
    if include_raw:
        entry["raw"] = record.get("Raw")
    return entry


def parse_args():
    parser = argparse.ArgumentParser(description="Scan listed files with TruffleHog; write JSON only if secrets are found.")
    parser.add_argument("-i", "--input", required=True, help="File containing the list of paths")
    parser.add_argument("-o", "--output", default="trufflehog_findings.json")
    parser.add_argument("--trufflehog", default="trufflehog", help="TruffleHog binary name or path")
    parser.add_argument("--profile-root", help="Folder whose first-level subfolders are the profiles")
    parser.add_argument("--profile-regex", default=r"[A-Za-z]{2,}\d+",
                        help="Path component pattern that identifies a profile (default: letters+digits)")
    parser.add_argument("--workers", type=int, default=4, help="Parallel scans (default 4)")
    parser.add_argument("--timeout", type=int, default=300, help="Seconds allowed per file (default 300)")
    parser.add_argument("--no-verification", action="store_true",
                        help="Do not verify secrets against live services (use when offline)")
    parser.add_argument("--include-raw", action="store_true",
                        help="Include the full secret value in the JSON (default: redacted only)")
    return parser.parse_args()


def main():
    args = parse_args()

    if shutil.which(args.trufflehog) is None and not Path(args.trufflehog).is_file():
        sys.exit("TruffleHog binary not found: {}".format(args.trufflehog))

    profile_root = Path(args.profile_root).expanduser().resolve() if args.profile_root else None
    profile_regex = re.compile(args.profile_regex)

    files, folders_skipped, missing_skipped = read_files(args.input)
    print("Files to scan  : {}".format(len(files)))
    print("Folders skipped: {}".format(folders_skipped))
    print("Missing skipped: {}".format(missing_skipped))

    extra_args = ["--no-verification"] if args.no_verification else []

    results = {}      # profile -> list of finding entries
    failures = []     # printed to console only, never written to the JSON

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(scan_file, args.trufflehog, f, extra_args, args.timeout): f
            for f in files
        }

        for done, future in enumerate(as_completed(futures), start=1):
            file_path = futures[future]
            findings, error = future.result()

            if error:
                failures.append((file_path, error))

            if findings:
                profile = detect_profile(file_path, profile_root, profile_regex)
                bucket = results.setdefault(profile, [])
                bucket.extend(to_entry(file_path, record, args.include_raw) for record in findings)
                print("[{}/{}] SECRETS FOUND ({}): {}".format(done, len(files), profile, file_path))
            else:
                print("[{}/{}] clean: {}".format(done, len(files), file_path))

    for file_path, error in failures:
        print("WARNING: scan failed for {} - {}".format(file_path, error), file=sys.stderr)

    total = sum(len(v) for v in results.values())
    if total == 0:
        print("\nNo secrets identified - no JSON file written.")
        return

    report = {profile: sorted(entries, key=lambda e: (e["file"], e["line"] or 0))
              for profile, entries in sorted(results.items())}

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    print("\n{} secret(s) across {} profile(s) written to: {}".format(
        total, len(report), Path(args.output).resolve()))


if __name__ == "__main__":
    main()
