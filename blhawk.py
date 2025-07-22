from modules.input_loader import inputLoader
import argparse

def main():
    parser = argparse.ArgumentParser(prog='BLHawk', description='Dead links aren\'t always dead!', epilog='version: 0.3.0')
    parser.add_argument('-u', '--url', type=str, help='example: https://www.target.com')
    #parser.add_argument('-l','--list', type=str, help='File containing URLs to check')
    #parser.add_argument('-t', '--thread', type=int, default=10, help='Number of threads to use (default: 10)')
    #parser.add_argument('-s', '--silent', help='show only result in output')
    #parser.add_argument('-h', '--help', action=help, help='Display this help message and exit')
    args = parser.parse_args()

    try:
        inputLoader(
                url=args.url,
                #raw_request=args.list,
                #cookie=args.filename,
                #thread=args.thread,
                #silent=args.silent,
            )
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C). Exiting...")

if __name__ == '__main__':
    main()