#!/usr/bin/env python3

from pathlib import Path
from typing import List
from zipfile import ZipFile, BadZipFile


def safe_extract(zip_file: Path, destination: Path) -> List[Path]:
    """
    Safely extract a ZIP archive and return all extracted file paths.
    """
    destination = destination.resolve()
    extracted_files: List[Path] = []

    with ZipFile(zip_file, "r") as archive:
        members = archive.infolist()

        # Validate paths before extracting anything
        for member in members:
            target = (destination / member.filename).resolve()

            if target != destination and destination not in target.parents:
                raise ValueError(
                    f"Unsafe path in {zip_file}: {member.filename}"
                )

        archive.extractall(destination)

        # Record extracted files, excluding directories
        for member in members:
            if not member.is_dir():
                extracted_files.append(
                    (destination / member.filename).resolve()
                )

    return extracted_files


def main() -> None:
    root_directory = Path(".").resolve()
    output_file = root_directory / "unzipped_paths.txt"

    # Identify ZIP files recursively
    zip_files = sorted(
        path
        for path in root_directory.rglob("*")
        if path.is_file() and path.suffix.lower() == ".zip"
    )

    report_lines: List[str] = []
    successful_archives = 0
    total_extracted_files = 0

    for zip_file in zip_files:
        destination = zip_file.with_suffix("")
        destination.mkdir(parents=True, exist_ok=True)

        print(f"Extracting: {zip_file}")
        print(f"Destination: {destination}")

        try:
            extracted_files = safe_extract(
                zip_file,
                destination,
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
            print(f"Skipped invalid ZIP: {zip_file}")
            report_lines.append(
                f"INVALID_ZIP: {zip_file.resolve()}"
            )
            report_lines.append("")

        except (OSError, ValueError) as error:
            print(f"Failed to extract {zip_file}: {error}")
            .append(
                f"FAILED_ZIP: {zip_file.resolve()}"
            )
            report_lines.append(f"ERROR: {error}")
            report_lines.append("")

    output_file.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print()
    print(f"ZIP files identified: {len(zip_files)}")
    print(
        f"ZIP files successfully extracted: "
        f"{successful_archives}"
    )
    print(f"Files extracted: {total_extracted_files}")
    print(f"Report written to: {output_file}")


if __name__ == "__main__":
    main()
