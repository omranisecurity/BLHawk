from modules.validator import url_validator
from modules.extractor import Extractor
import requests
from typing import Optional


def input_loader(url: Optional[str]) -> None:
    """Load `url` content and pass it to the extractor.

    Keeps behavior simple and prints errors for invalid or unreachable URLs.
    """
    if not url:
        print("[~] No URL provided")
        return

    if not url_validator(url):
        print(f"[~] [The URL is not valid] | URL: {url}")
        return

    session = requests.Session()
    try:
        resp = session.get(url, timeout=5)
        Extractor(resp.text)
    except requests.RequestException as e:
        print(f"[ERROR] {url} - {e}")


# Backwards compatible name used by the CLI and tests
inputLoader = input_loader