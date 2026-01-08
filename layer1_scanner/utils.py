import os
from datetime import datetime

# Use a LIGHT scan while wiring the layers; you can add scripts later
NMAP_ARGUMENTS = "-sV"  # quick version scan, no vuln scripts


def log(message: str, level: str = "INFO"):
    print(f"[{datetime.utcnow().isoformat()}] [{level}] {message}")


def sanitize_filename(name: str) -> str:
    return (
        name.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )


def ensure_results_folder():
    os.makedirs("results", exist_ok=True)
