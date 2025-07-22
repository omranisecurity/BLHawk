from modules.validator import url_validator
from modules.extractor import Extractor
import requests

def inputLoader(url):
    if url_validator(url):
        try:
            response = requests.get(url, timeout=5)
            content = response.text
            Extractor(content)

        except requests.RequestException as e:
            print(f"[ERROR] {url} - {e}")
    else:
        print(f"[~] [The URL is not valid] | URL: {url}")