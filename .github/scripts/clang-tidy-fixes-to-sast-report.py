#!/usr/bin/env python3

"""Clang-tidy fixes SAST reports in markdown and YAML formats.

Convert the YAML file produced by clang-tidy-diff containing warnings and
suggested fixes to a SAST reports in markdown and YAML formats.
"""

import argparse
import os
import sys
import yaml
from pathlib import Path

import helpers

def create_argument_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(description="Convert clang-tidy output to Github Actions")
    parser.add_argument(
        "--fixes-file",
        type=str,
        required=True,
        help="Path to the clang-tidy fixes YAML",
    )
    parser.add_argument(
        "--base-directory",
        type=str,
        required=True,
        help="Path to the root of the source (could be pdns/dnsdistdist, pdns/recursordist or the root of the repository for the auth)",
    )
    parser.add_argument(
        "--output-yaml-file",
        type=str,
        required=True,
        help="Path to the SAST report in YAML format",
    )
    parser.add_argument(
        "--output-md-file",
        type=str,
        required=True,
        help="Path to the SAST report in markdown format",
    )
    return parser.parse_args()


def main():
    """Start the script."""
    args = create_argument_parser()

    fixes = helpers.load_fixes_file(args.fixes_file)

    if not fixes:
        print("No diagnostics or warnings produced by clang-tidy")
        return 0

    fixes = fixes["Diagnostics"]
    issues = {}

    for fix in fixes:
        name = fix["DiagnosticName"]
        level = fix["Level"]
        directory = fix["BuildDirectory"]
        diagnostic = fix["DiagnosticMessage"]
        offset = diagnostic["FileOffset"]
        filename = diagnostic["FilePath"]
        message = diagnostic["Message"]

        if filename == "":
            print(f"Meta error message from `{directory}`: {message}")
            continue

        full_filename = filename
        full_filename = Path(full_filename)
        full_filename = full_filename.as_posix() if full_filename.is_absolute() else os.path.join(directory, filename)

        try:
            file_contents = helpers.load_file(full_filename)
        except OSError:
            # Skip in case the file can't be found. This is usually one of
            # those "too many errors emitted, stopping now" clang messages.
            print(f"Skipping `{full_filename}` because it is not found")
            continue

        line = helpers.get_line_from_offset(file_contents, offset)
        rel_filename = Path(full_filename).resolve().relative_to(args.base_directory)

        diagnostic["FileLine"] = line
        diagnostic["FilePath"] = rel_filename

        if not name in issues:
            issues[name] = []
        issues[name].append(f"{rel_filename}:{line}: {message}")

        if "Ranges" in diagnostic:
            for drange in diagnostic["Ranges"]:
                drange["FilePath"] = rel_filename
                drange["FileLine"] = helpers.get_line_from_offset(file_contents, drange["FileOffset"])

    # User-friendly printout
    with open(args.output_md_file, "w+", encoding="utf-8") as md_fp:
        print("### SAST analysis\n", file=md_fp)

        for [name, entries] in issues.items():
            print(f"## {name}", file=md_fp)
            for entry in entries:
                print(f"- {entry}", file=md_fp)

    with open(args.output_yaml_file, "w+", encoding="utf-8") as yaml_fp:
        yaml.dump(fixes, yaml_fp)

    return 0

if __name__ == "__main__":
    sys.exit(main())
