from modules.input_loader import inputLoader
import argparse

def main():
    parser = argparse.ArgumentParser(prog='BLHawk', description='Dead links aren\'t always dead!', epilog='version: 0.3.0')
    parser.add_argument('-u', '--url', type=str, help='example: https://www.target.com')
    parser.add_argument('--src', type=str, help='Path to source code directory for scan')
    #parser.add_argument('-l','--list', type=str, help='File containing URLs to check')
    #parser.add_argument('-t', '--thread', type=int, default=10, help='Number of threads to use (default: 10)')
    #parser.add_argument('-s', '--silent', help='show only result in output')
    #parser.add_argument('-h', '--help', action=help, help='Display this help message and exit')
    args = parser.parse_args()

    try:
        if args.url:
            inputLoader(
                url=args.url,
                #raw_request=args.list,
                #cookie=args.filename,
                #thread=args.thread,
                #silent=args.silent,
            )
        elif args.src:
            from modules.scan import scan_source
            scan_source(args.src)
        else:
            print("[!] Please provide either --url or --src argument.")
            exit(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C). Exiting...")

if __name__ == '__main__':
    main()