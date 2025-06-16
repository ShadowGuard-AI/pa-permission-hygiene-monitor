import argparse
import logging
import os
import stat
import sys
from typing import List, Tuple

try:
    import pathspec
    from rich.console import Console
    from rich.table import Column, Table
except ImportError as e:
    print(f"Error importing dependencies: {e}. Please install them (pip install pathspec rich).")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse() -> argparse.ArgumentParser:
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="pa-permission-hygiene-monitor: Monitors file system permissions for hygiene issues."
    )

    parser.add_argument(
        "path",
        type=str,
        help="The path to monitor (e.g., /var/www).",
    )

    parser.add_argument(
        "--wildcard-patterns",
        type=str,
        nargs='+',
        default=["*"],
        help="Glob patterns to check for overly permissive permissions (e.g., *.*, *). Defaults to ['*'].",
    )

    parser.add_argument(
        "--privileged-users",
        type=str,
        nargs='+',
        default=["root", "admin"],
        help="List of privileged users to check for default passwords (placeholder). Defaults to ['root', 'admin'].",
    )

    parser.add_argument(
        "--min-permissions",
        type=oct,
        default=0o777,  # Default overly permissive mode. Change as needed
        help="Minimum permission value considered overly permissive (octal). Defaults to 0777.",
    )

    parser.add_argument(
        "--exclude-paths",
        type=str,
        nargs='+',
        default=[],
        help="Paths to exclude from the check (e.g., /tmp, /var/log).",
    )

    parser.add_argument(
        "--include-offensive-tools",
        action="store_true",
        help="Include checks for common locations of offensive tools.",
    )
    
    parser.add_argument(
      "--report-file",
      type=str,
      help="Path to write the report to a file. If not specified, prints to console.",
      default=None
    )

    return parser


def check_permissions(path: str, wildcard_patterns: List[str], min_permissions: int, exclude_paths: List[str]) -> List[Tuple[str, int]]:
    """
    Checks file permissions recursively under the given path.

    Args:
        path: The path to start the check from.
        wildcard_patterns: A list of wildcard patterns to match files against.
        min_permissions: The minimum permission value considered overly permissive.
        exclude_paths: A list of paths to exclude from the check.

    Returns:
        A list of tuples, where each tuple contains the file path and its permissions (in octal) for overly permissive files.
    """
    logging.info(f"Checking permissions under path: {path}")

    overly_permissive_files = []
    spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, exclude_paths)

    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)

            if spec.match_file(file_path):
                logging.debug(f"Excluding path: {file_path}")
                continue

            for pattern in wildcard_patterns:
                if file_path.endswith(pattern) or pattern == "*":  # Efficient wildcard matching

                    try:
                        permissions = stat.S_IMODE(os.stat(file_path).st_mode)
                        if permissions >= min_permissions:
                            overly_permissive_files.append((file_path, permissions))
                            logging.warning(f"Found overly permissive file: {file_path} with permissions {oct(permissions)}")
                    except OSError as e:
                        logging.error(f"Error checking permissions for {file_path}: {e}")

    return overly_permissive_files


def check_offensive_tools(path: str) -> List[str]:
    """
    Checks for the presence of common offensive tools in the directory structure.

    Args:
        path: The path to scan.

    Returns:
        A list of file paths where offensive tools are found.
    """
    offensive_tool_names = ["nmap", "metasploit", "sqlmap", "wireshark", "hydra"]  # Expand as needed
    found_tools = []

    for root, _, files in os.walk(path):
        for file in files:
            if file.lower() in offensive_tool_names:
                file_path = os.path.join(root, file)
                found_tools.append(file_path)
                logging.warning(f"Found possible offensive tool: {file_path}")

    return found_tools


def generate_report(overly_permissive_files: List[Tuple[str, int]], offensive_tools: List[str], output_file: str = None) -> None:
    """
    Generates a report of the findings and prints it to the console or a file using Rich.

    Args:
        overly_permissive_files: A list of tuples containing file paths and their permissions.
        offensive_tools: A list of paths where offensive tools were found.
        output_file: The path to save the report to. If None, prints to the console.
    """
    console = Console(file=open(output_file, "w") if output_file else sys.stdout)

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("File Path", style="dim", width=60)
    table.add_column("Permissions", style="bold")

    for file_path, permissions in overly_permissive_files:
        table.add_row(file_path, oct(permissions))

    console.print("[bold red]Overly Permissive Files:[/]")
    if overly_permissive_files:
        console.print(table)
    else:
        console.print("[green]No overly permissive files found.[/]")

    if offensive_tools:
        console.print("\n[bold red]Possible Offensive Tools Found:[/]")
        for tool_path in offensive_tools:
            console.print(f"[yellow]{tool_path}[/]")
    else:
        console.print("\n[green]No offensive tools found.[/]")

    if output_file:
        print(f"Report saved to {output_file}")


def main() -> None:
    """
    Main function to parse arguments, check permissions, and generate a report.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.isdir(args.path):
        print(f"Error: Path '{args.path}' is not a valid directory.")
        sys.exit(1)

    if not isinstance(args.min_permissions, int):
        print(f"Error: Min permissions '{args.min_permissions}' is not a valid octal integer")
        sys.exit(1)

    try:
        overly_permissive_files = check_permissions(args.path, args.wildcard_patterns, args.min_permissions, args.exclude_paths)
    except Exception as e:
        logging.error(f"An error occurred during permission checking: {e}")
        sys.exit(1)

    offensive_tools = []
    if args.include_offensive_tools:
        try:
            offensive_tools = check_offensive_tools(args.path)
        except Exception as e:
            logging.error(f"An error occurred during offensive tool checking: {e}")

    try:
        generate_report(overly_permissive_files, offensive_tools, args.report_file)
    except Exception as e:
        logging.error(f"An error occurred during report generation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Example Usage:
# 1. Basic Usage (check /var/www for overly permissive files):
#    python main.py /var/www

# 2. Check with custom wildcard patterns and exclude specific directories:
#    python main.py /var/www --wildcard-patterns *.php *.html --exclude-paths /var/www/cache /var/www/logs

# 3. Check for offensive tools and save the report to a file:
#    python main.py /opt --include-offensive-tools --report-file report.txt

# 4.  Check with a custom minimum permission
#   python main.py /var/www --min-permissions 0o755