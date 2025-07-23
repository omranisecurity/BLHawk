import requests
from colorama import Fore, Style
from urllib.parse import urlparse

SERVICES = {
    "telegram": {
        "domains": ["t.me", "telegram.me"],
        "check": lambda resp: "If you have" in resp.text and "you can contact" in resp.text and "right away." in resp.text,
    },
    "youtube": {
        "domains": ["www.youtube.com", "youtube.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "medium": {
        "domains": ["medium.com"],
        "check": lambda resp: '<title data-rh="true">Medium</title>' in resp.text,
    },
    "github": {
        "domains": ["github.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "Soundcloud": {
        "domains": ["soundcloud.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "Google Play (App/Developer Page)	": {
        "domains": ["play.google.com"],
        "check": lambda resp: resp.status_code == 404,
    },
}

def get_service_by_host(host):
    for service_name, service_info in SERVICES.items():
        if host in service_info["domains"]:
            return service_name, service_info
    return None, None

def check_vulnerability(url):
    parsed = urlparse(url)
    host = parsed.netloc

    service_name, service_info = get_service_by_host(host)

    if service_info:
        try:
            response = requests.get(url, timeout=5)
            is_vuln = service_info["check"](response)

            if is_vuln:
                print(f"{Fore.GREEN}[VULNERABLE] {url} ({service_name}){Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[NOT VULNERABLE] {url} ({service_name}){Style.RESET_ALL}")
            
        except requests.RequestException as e:
            print(f"[ERROR] {url} - {e}")