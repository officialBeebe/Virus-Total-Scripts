import base64
import logging
import os
import pprint

import requests
import validators
from dotenv import dotenv_values


class VirusTotalAPI:
    def __init__(self, api_key="acf878b3abf89c5d3a4136720301351f307d0746f83ed05a0e7cc0133ecadc33"):
        self.api_key = api_key
        if not self.api_key:
            raise ValueError("No API key provided.")
        self.base = 'https://www.virustotal.com/api/v3'
        self.headers = {"accept": "application/json", "x-apikey": self.api_key}

    @staticmethod
    def base64_encode(url):
        """
        Must encode the URL before using it in the API, or use url_id.split("-")[1].
        """
        return base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")

    def upload_file(self, file, password):
        """
        Upload a file for analysis.
        :param file: Path to the file to upload
        :param password: Password for the file (default is None)
        :return: JSON response
        """
        try:
            files = {"file": (file, open(file, "rb"), "text/plain")}
            data = {"password": password}
            return requests.post(f"{self.base}/files", headers=self.headers, files=files, data=data).json()
        except FileNotFoundError as e:
            print(f"File not found: {e}")
            return None

    def get_url_or_file_analysis(self, id):
        """
        Get the URL or file analysis by its base64-encoded ID.
        :param id: URL or file ID
        :return: JSON response
        """
        return requests.get(f"{self.base}/analyses/{id}", headers=self.headers).json()

    def get_file_report(self, file_hash):
        """
        Get a report for the file by its hash.
        :param file_hash: SHA-256 hash of the file
        :return: JSON response
        """
        return requests.get(f"{self.base}/files/{file_hash}", headers=self.headers).json()

    def scan_url(self, url):
        """
        Submit a URL for analysis.
        :param url: URL to scan
        :return: JSON response
        """
        payload = {"url": url}

        return requests.post(f"{self.base}/urls", headers=self.headers, data=payload).json()

    def get_url_report(self, id):
        """
        Get a report for the URL by its base64-encoded URL.
        :param id: URL id returned by scan_url() to get the report for
        :return: JSON response
        """
        return requests.get(f"{self.base}/urls/{id}", headers=self.headers).json()

    def get_domain_report(self, domain):
        """
        Get a report for a domain.
        :param domain: Domain name (e.g., example.com)
        :return: JSON response
        """
        return requests.get(f"{self.base}/domains/{domain}", headers=self.headers).json()

    def get_ip_report(self, ip):
        """
        Get a report for an IP address.
        :param ip: IP address
        :return: JSON response
        """
        return requests.get(f"{self.base}/ip_addresses/{ip}", headers=self.headers).json()

    ## Good to Have

    ## Advanced

    ## Utils
    @staticmethod
    def get_api_key():
        """
        Retrieve the API key from Docker Secret, environment variable, or .env file.
        Prioritize Docker Secret first, then environment variable, then .env.
        """
        # 1. Try to read from Docker Secret
        secret_path = "/run/secrets/virustotal_api_key"
        if os.path.exists(secret_path):
            with open(secret_path, "r") as f:
                api_key = f.read().strip()
            if api_key:
                return api_key
            else:
                raise ValueError("API_KEY found in Docker Secret is empty.")

        # 2. Try to get the API key from an environment variable
        api_key = os.getenv("API_KEY")
        if api_key:
            return api_key

        # 3. Fallback to .env file
        project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        env_path = os.path.join(project_dir, '.env')
        config = dotenv_values(env_path)
        api_key = config.get("API_KEY")

        if api_key:
            return api_key

    @staticmethod
    def validate_url(url):
        # Set up logging
        logging.basicConfig(level=logging.INFO)

        if not validators.url(url):
            logging.error(f"Invalid URL: {url}")
            return False
        return True

    def rescan_file(self, file_hash):
        try:
            response = requests.post(f"{self.base}/files/{file_hash}/analyse", headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f"Failed to rescan file {file_hash}: {e}")
            return None


"""
    - Most Popular:
        - **Upload a file for scanning**
        - **Get a file report by hash**
        - **Scan a URL**
        - **Get a URL analysis report**
        - **Get a domain report**
        - **Get an IP address report**
    - Good to Have:
        - Rescan URL/File (POST /urls-analyse, POST /files-analyse)
        - Comments management (GET/POST comments endpoints)
        - Votes on objects
    - Advanced:
        - Relationships (GET relationships endpoints)
        - Behavior analysis
        - MITRE ATT&CK integration
"""

if __name__ == "__main__":
    # api_key = input("Enter your VirusTotal API key: ")
    # vt = VirusTotalAPI(api_key)
    #
    # # Example usage
    # url = "https://www.virustotal.com/"
    # scan = vt.scan_url(url)
    # url_id = scan["data"]["id"]
    # print(url)
    # print(scan)
    # print(f"URL ID: {url_id}")
    # print(type(url_id))
    # print("Attempting to get URL report...")
    #
    # url_report = vt.get_url_report(url_id)
    # print(url_report)

    vt = VirusTotalAPI()

    # url = "http://www.virustotal.com/"
    # url_scan = vt.scan_url(url)
    # url_id = url_scan['data']['id'].split("-")[1]
    # print("scan_url URL: ", url_scan, end="\n\n")
    #
    # print(f"\n\n{" * " * 25}\n\n")
    #
    # print("scan_url ID: ", url_id, end="\n\n")
    #
    # print(f"\n\n{" * " * 25}\n\n")
    #
    # url_report = vt.get_url_report(url_id)
    # print("URL Report: ", json.dumps(url_report, indent=4), end="\n\n")
    # # pprint.pprint(url_report, indent=4)
    #
    # print(f"\n\n{" * " * 25}\n\n")

    domain_list = [
        # "virustotal.com"  # VirusTotal
        # "fidelity.com",  # Financial services
        "attack.mitre.org",  # MITRE ATT&CK framework
        # "nsa.gov",  # U.S. National Security Agency
        # "akamai.com",  # CDN and security services
    ]

    for domain in domain_list:
        domain_report = vt.get_domain_report(domain)
        print(f"Domain Report for {domain}: ")
        pprint.pprint(domain_report, indent=4)

    print(f"\n\n{" * " * 25}\n\n")

    ip_address_list = [
        # "192.168.1.1",  # Local network IP
        # "10.0.0.1",  # Private network IP
        # "172.16.0.1",  # Private network IP
        "8.8.8.8",  # Google Public DNS
        # "1.1.1.1"  # Cloudflare DNS
    ]
    for ip in ip_address_list:
        ip_report = vt.get_ip_report(ip)
        print(f"IP Address Report for {ip}: ")
        pprint.pprint(ip_report, indent=4)

    # print(f"\n\n{" * " * 25}\n\n")
    #
    # files = ["VirustotalAPI.py"]
    # for file in files:
    #     upload_response = vt.upload_file(file, password=None)
    #     print(f"Uploaded {file}: ")
    #     pprint.pprint(upload_response, indent=4)
    #
    #     print("Analysis is queued. Waiting...")
    #     max_retries = 10
    #     retries = 0
    #     while retries < max_retries:
    #         try:
    #             upload_analysis = vt.get_url_or_file_analysis(upload_response["data"]["id"])
    #             status = upload_analysis["data"]["attributes"]["status"]
    #
    #             # Wait 5 seconds for the first check
    #             if retries == 0:
    #                 time.sleep(5)
    #                 retries += 1
    #                 continue
    #
    #             if status == "queued":
    #                 time.sleep(10)
    #                 retries += 1
    #                 continue
    #             elif status == "completed":
    #                 print("Analysis completed.")
    #                 pprint.pprint(upload_analysis, indent=4)
    #                 upload_sha256 = upload_analysis["meta"]["file_info"]["sha256"]
    #                 break
    #             else:
    #                 print(f"Unexpected status: {status}. Exiting.")
    #                 break
    #
    #         except Exception as e:
    #             print(f"Exception: {e}")
    #             break
    #     else:
    #         print("Max retries reached. Exiting.")
    #         continue

# TODO: Wrap the HTTP requests in a dictionary and add the logic above to a generate_report() method.
