# BLHawk - Dead links aren't always dead!

BLHawk checks URLs for broken link vulnerabilities on popular services like Telegram, YouTube, Medium, and GitHub.

---

## Features

- Supports the following services:
  - Telegram (`t.me`, `telegram.me`)
  - YouTube (`youtube.com`, `www.youtube.com`)
  - Medium (`medium.com`)
  - GitHub (`github.com`)
  - Soundcloud (`soundcloud.com`)
  - Google Play (App/Developer Page) (`play.google.com`)
  - Buy Me a Coffee (`buymeacoffee.com`)
  - Dribbble (`dribbble.com`)
- Sends HTTP requests and analyzes server responses to detect vulnerabilities
- Color-coded output (green for vulnerable, red for not vulnerable)

Future Work:
More services will be added soon with contributions from the community to enhance the tool’s coverage and capabilities.

---

### Prerequisites

- Python 3.x must be installed.
- Internet access to install dependencies.

### Installation

1. Clone the repository:
     ```sh
     git clone https://github.com/omranisecurity/BLHawk.git
     cd BLHawk
     ```
2. Install required packages:
     ```sh
     pip install -r requirements.txt
     ```

### Basic Usage

Scan a single URL:

```sh
python blhawk.py -u https://target.com/example
```

## Roadmap

- [x] Support for scanning single URLs
- [ ] Add support for scanning multiple URLs from a list file
- [ ] Implement flags such as `--silent`, `--output`, `--thread`, and `--help`
- [ ] Expand supported services with community contributions

## Contributing
Contributions are welcome! Please open an issue before submitting pull requests. This helps us discuss ideas and track bugs effectively.
