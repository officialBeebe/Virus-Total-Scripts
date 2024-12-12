import argparse
import re
import time
from pprint import pprint

import VirusTotalAPI


def main(args=None, vt=None):
    # Get the API key from somewhere lol
    api_key = VirusTotalAPI.VirusTotalAPI.get_api_key()
    vtapi = VirusTotalAPI.VirusTotalAPI(api_key)  # Instantiate the VirusTotalAPI object

    # Setup parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="Virus Total API Key.", required=False)
    parser.add_argument("-u", "--url", help="Output report for URL.", required=False)
    parser.add_argument("-f", "--file", help="Output report for file.", required=False)
    parser.add_argument("-p", "--password", help="Password for file.", required=False)
    parser.add_argument("-t", "--timeout", help="Timeout for file analysis.", required=False)
    parser.add_argument("-r", "--retries", help="Number of retries for file analysis.", required=False)
    parser.add_argument("-d", "--domain", help="Output report for domain.", required=False)
    parser.add_argument("-i", "--ip", help="Output report for IP address", required=False)

    # Parse args
    args = parser.parse_args()

    key: str = args.key or api_key
    url = args.url if args.url else None
    file: str = args.file if args.file else None
    password: str = args.password if args.password else None
    timeout: int = int(args.timeout) if args.timeout else 30
    retries: int = int(args.retries) if args.retries else 10
    domain: str = re.sub(r"^[a-zA-Z]+://", "", args.domain) if args.domain else None
    ip: str = args.ip if args.ip else None

    # Args controller
    if not key:
        raise ValueError(
            "This program requires an API key to run. Get one from https://www.virustotal.com/gui/join-us\n\nIf you have a key, enter the flag --key followed by your key.")

    if url:
        scan = vtapi.scan_url(url)
        url_id = scan["data"]["id"].split("-")[1]
        url_report = vtapi.get_url_report(url_id)
        pprint(url_report)

    if file:
        upload_response = vtapi.upload_file(file, password)
        print("File uploaded. Analysis queued. Waiting", end="", flush=True)

        max_retries = retries
        retry_count = 0
        while retry_count < max_retries:
            try:
                upload_analysis = vtapi.get_url_or_file_analysis(upload_response["data"]["id"])
                status = upload_analysis["data"]["attributes"]["status"]

                # Wait 5 seconds for the first 5 checks
                if retry_count < 5:
                    retry_count += 1
                    time.sleep(5)
                    print(".", end="", flush=True)
                    continue

                # Wait x amount of seconds for subsequent checks
                if status == "queued":
                    retry_count += 1
                    time.sleep(timeout)
                    print(".", end="", flush=True)
                    continue
                elif status == "completed":
                    print(" success!", end="\n\n", flush=True)
                    pprint(upload_analysis)
                    break
                else:
                    print(f"Unexpected status: {status}. Exiting.", end="\n\n", flush=True)
                    break

            except Exception as e:
                print(f"Exception: {e}", end="\n\n", flush=True)
                break

        else:
            print("failed. Timeout after maximum retries.", end="\n\n", flush=True)

    if domain:
        domain_report = vtapi.get_domain_report(domain)
        pprint(domain_report)

    if ip:
        ip_report = vtapi.get_ip_report(ip)
        pprint(ip_report)


if __name__ == "__main__":
    main()
