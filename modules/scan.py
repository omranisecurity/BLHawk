import requests
from colorama import Fore, Style, init
from urllib.parse import urlparse

init(autoreset=True)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; BLHawk/0.3.0)"})

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
    "soundcloud": {
        "domains": ["soundcloud.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "googleplay": {
        "domains": ["play.google.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "Buy Me a Coffee": {
        "domains": ["buymeacoffee.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "dribbble": {
        "domains": ["dribbble.com"],
        "check": lambda resp: resp.status_code == 404 and 'that page is gone' in resp.text,
    },
    "npmjs": {
        "domains": ["www.npmjs.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "pypi": {
        "domains": ["pypi.org"],
        "check": lambda resp: resp.status_code == 404 and 'We looked everywhere but couldn\'t find this page' in resp.text,
    },
    "Myket": {
        "domains": ["myket.ir"],
        "check": lambda resp: resp.status_code == 404,
    },
    "CafeBazaar": {
        "domains": ["cafebazaar.ir"],
        "check": lambda resp: resp.status_code == 404,
    },
    "DEV Community": {
        "domains": ["dev.to"],
        "check": lambda resp: resp.status_code == 404 and 'page not found' in resp.text
    },
    "Vimeo": {
        "domains": ["vimeo.com"],
        "check": lambda resp: resp.status_code == 404,
    },
    "twitch": {
        "domains": ["twitch.tv"],
        "check": lambda resp: resp.status_code == 404,
    },
    "GitLab": {
        "domains": ["gitlab.com"],
        "check": lambda resp: resp.status_code in [301, 302, 303, 307, 308] and 'https://gitlab.com/users/sign_in' in resp.headers.get('Location', ''),
    },
    "Pinterest": {
        "domains": ["pinterest.com","www.pinterest.com"],
        "check": lambda resp: "User not found." in resp.text,
    }
}
def get_service_by_host(host):
    for service_name, service_info in SERVICES.items():
        if host in service_info["domains"]:
            return service_name, service_info
    return None, None

def check_vulnerability(url):
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc

    service_name, service_info = get_service_by_host(host)

    if not service_info:
        return

    try:
        response = SESSION.get(url, timeout=5, allow_redirects=False)
        is_vuln = service_info["check"](response)

        if is_vuln:
            print(f"{Fore.GREEN}[VULNERABLE] {url} ({service_name}){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[NOT VULNERABLE] {url} ({service_name}){Style.RESET_ALL}")

    except requests.RequestException as e:
        print(f"[ERROR] {url} - {e}")