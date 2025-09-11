import requests
import re
from pathlib import Path

# Simple regex to match URLs
url_pattern = r'https?://[^\s"\']+'

# Only scan text-based files
TEXT_EXTENSIONS = [".js", ".html", ".md", ".txt"]
files_to_scan = [f for f in Path(".").rglob("*.*") if f.suffix in TEXT_EXTENSIONS]

broken_links = []

def check_link(link, file_path):
    try:
        r = requests.get(link, timeout=5, allow_redirects=True)
        if r.status_code == 404:
            broken_links.append(f"{file_path}: {link}")
    except Exception:
        broken_links.append(f"{file_path}: {link} (error)")

# Iterate through all selected files
for file in files_to_scan:
    try:
        with open(file, "r", encoding="utf-8") as f:
            for line in f:
                for link in re.findall(url_pattern, line):
                    check_link(link, file)
    except Exception:
        continue

# Write broken links report to a temporary file
with open("broken_links_report.txt", "w", encoding="utf-8") as f:
    if broken_links:
        for link in broken_links:
            f.write(link + "\n")
    else:
        f.write("No broken links found.\n")
