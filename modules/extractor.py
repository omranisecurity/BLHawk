from modules.scan import check_vulnerability
import re
from typing import Iterable

URL_RE = re.compile(r"https?://[^\s'\">]+")


def extractor(content: str) -> None:
    """Extract URLs from `content` and check each for vulnerabilities."""
    if not content:
        return

    for url in URL_RE.findall(content):
        check_vulnerability(url)


# Backwards compatible name used elsewhere in the project
Extractor = extractor