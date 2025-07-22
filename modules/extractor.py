from modules.scan import check_vulnerability
import re

def Extractor(content):
    for line in content.splitlines():
        urls = re.findall(r"https?://[^\s'\">]+", line)
        for url in urls:
            check_vulnerability(url)