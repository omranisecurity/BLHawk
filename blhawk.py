from modules.input_loader import inputLoader
import argparse


VERSION = "0.4.0"


def main():
    parser = argparse.ArgumentParser(prog='BLHawk', description="Dead links aren't always dead!", epilog=f'version: {VERSION}')
    parser.add_argument('-u', '--url', type=str, help='example: https://www.target.com')
    args = parser.parse_args()

    try:
        inputLoader(url=args.url)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C). Exiting...")


if __name__ == '__main__':
    main()