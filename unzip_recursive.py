#!/usr/bin/env python3

from pathlib import Path
from zipfile import ZipFile, BadZipFile


def safe_extract(zip_file: Path, destination: Path) -> list"""
    Safely extract a ZIP archive and return the extracted file paths.
    Prevents ZIP path-traversal attacks.
    """
    destination = destination.resolve()
    extracted_files = []

    with ZipFile(zip_file, "r") as archive:
        for member in archive.infolist():
            target = (destination / member.filename).resolve()

            # Prevent entries such as ../../malicious_file
            if target != destination and destination not in target.parents:
                raise ValueError(
                    f"Unsafe path in {zip_file}: {member.filename}"
                )

        archive.extractall(destination)

        # Record files only, excluding directory entries
        for member in archive.infolist():
            if not member.is_dir():
                extracted_file = (
                    destination / member.filename
                ).resolve()
                extracted_files.append(extracted_file)

    return extracted_files


def main() -> None:
    root_directory = Path(".").resolve()
    output_file = root_directory / "unzipped_paths.txt"

    # Create the list before extraction so newly extracted nested ZIPs
    # are not unintentionally processed during this run.
    zip_files = [
        path
        for path in root_directory.rglob("*")
        if path.is_file() and path.suffix.lower() == ".zip"
    ]

    report_lines = []
    successful_archives = 0
    total_extracted_files = 0

    for zip_file in zip_files:
        destination = zip_file.with_suffix("")
        destination.mkdir(parents=True, exist_ok=True)

        print(f"Extracting: {zip_file}")
        print(f"Destination: {destination}")

        try:
            extracted_files = safe_extract(
                zip_file=zip_file,
                destination=destination,
            )

            successful_archives += 1
            total_extracted_files += len(extracted_files)

            report_lines.append(f"ZIP: {zip_file.resolve()}")
            report_lines.append(
                f"EXTRACTED_TO: {destination.resolve()}"
            )

            for extracted_file in extracted_files:
                report_lines.append(f"FILE: {extracted_file}")

            report_lines.append("")

        except BadZipFile:
            print(f"Skipped invalid ZIP file: {zip_file}")
            report_lines.append(f"INVALID_ZIP: {zip_file.resolve()}")
            report_lines.append("")

        except (OSError, ValueError) as error:
            print(f"Failed to extract {zip_file}: {error}")
            report_lines.append(f"FAILED_ZIP: {zip_file.resolve()}")
            report_lines.append(f"ERROR: {error}")
            report_lines.append("")

    output_file.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print()
    print(f"ZIP files identified: {len(zip_files)}")
    print(f"ZIP files successfully extracted: {successful_archives}")
    print(f"Files extracted: {total_extracted_files}")
    print(f"Report written to: {output_file}")


if __name__ == "__main__":
    main()
