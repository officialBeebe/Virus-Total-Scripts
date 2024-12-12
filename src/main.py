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
    parser.add_argument("-d", "--domain", help="Output report for domain.", required=False)
    parser.add_argument("-i", "--ip", help="Output report for IP address", required=False)

    # Parse args
    args = parser.parse_args()

    key: str = args.key or api_key
    url = args.url
    file: str = args.file
    password: str = args.password
    domain: str = re.sub(r"^[a-zA-Z]+://", "", args.domain) if args.domain else None
    ip: str = args.ip

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
        print("File uploaded. Analysis queued. Waiting... ", end="")

        max_retries = 10
        retries = 0
        while retries < max_retries:
            try:
                upload_analysis = vtapi.get_url_or_file_analysis(upload_response["data"]["id"])
                status = upload_analysis["data"]["attributes"]["status"]

                # Wait 15 seconds before the first check
                if retries == 0:
                    retries += 1
                    time.sleep(15)

                # Wait 5 seconds for subsequent checks
                if status == "queued":
                    retries += 1
                    time.sleep(5)
                elif status == "completed":
                    print("success!", end="\n\n")
                    pprint(upload_analysis)
                    break
                else:
                    print(f"Unexpected status: {status}. Exiting.")
                    break

            except Exception as e:
                print(f"Exception: {e}")
                break

        else:
            print("failed. Timeout after maximum retries.")

    if domain:
        domain_report = vtapi.get_domain_report(domain)
        pprint(domain_report)

    if ip:
        ip_report = vtapi.get_ip_report(ip)
        pprint(ip_report)


if __name__ == "__main__":
    main()
