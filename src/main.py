import argparse
import json
import os
from pprint import pprint

import vt
from dotenv import dotenv_values
from vt.object import WhistleBlowerDict


def main(args=None):
    # Get the API key from somewhere lol
    api_key = get_api_key()

    # Setup parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="API key for VirusTotal.", required=False)
    parser.add_argument("-d", "--debug", help="Print the raw object data.", action="store_true", default=False)
    parser.add_argument("-u", "--url", help="URL to scan. Returns analysis results and stats.", required=False)
    parser.add_argument("-f", "--file", help="File to scan. Returns analysis results and stats.", required=False)
    parser.add_argument("-c", "--comments", help="Show comments for the scanned object. Default 10.", type=int,
                        default=10, required=False)
    parser.add_argument("-o", "--output", help="Output the results to a txt file.", action="store_true", required=False)

    # Parse args
    args = parser.parse_args()
    key: str = args.key or api_key
    url: str = args.url
    file: str = args.file
    debug: bool = args.debug
    output: str = args.output
    comments: int = args.comments

    # Handle args
    if not key:
        raise ValueError(
            "This program requires an API key to run. Get one from https://www.virustotal.com/gui/join-us\n\nIf you have a key, enter the flag --key followed by your key.")

    if url:
        url_object = get_url_object(url, key)
        analysis_results = url_object.last_analysis_results
        analysis_stats = url_object.last_analysis_stats

        if debug:
            pprint(url_object.to_dict())

        if output:
            output_analysis_results(analysis_results)


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


def custom_serializer(obj):
    if isinstance(obj, WhistleBlowerDict):
        return dict(obj)  # Convert WhistleBlowerDict to standard dict
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def transform_results(results):
    return [{"engine_name": engine_name, **details} for engine_name, details in results.items()]


def output_analysis_results(results):
    # print("DEBUG: Results received:", results)
    category_order = {
        "malicious": 0,
        "suspicious": 1,
        "undetected": 2,
        "harmless": 3,
        "timeout": 4
    }

    transformed_results = transform_results(results)

    sorted_results = sorted(transformed_results, key=lambda x: category_order.get(x["category"], float("inf")))
    for entry in sorted_results:
        print(json.dumps(
            {
                "Engine": entry["engine_name"],
                "Category": entry["category"],
                "Method": entry["method"],
                "Result": entry["result"]
            },
            indent=4)
        )


def get_url_object(url, key):
    # TODO: Load the API key securely from a remote server, OR load a .env everytime?

    if not key:
        raise ValueError("API_KEY not in .env file...")

    try:
        # Use context manager to establish a connection to the VirusTotal API, perform an action, and close the
        # connection
        with vt.Client(key) as Client:
            url_id = vt.url_id(url)  # VirusTotal backend hashes the URL
            url_object = Client.get_object(f"/urls/{url_id}")

            return url_object


    except Exception as e:
        print(f"EXCEPTION: {e}")


if __name__ == "__main__":
    main()

# TODO: Implement fzf interface for selecting objects in the file system to scan. Also add object scanning
#  functionality...

# TODO: Implement argparse for command-line arguments to specify scanning a single URL, many URLS, or a file system
#  object or collection of objects.

# TODO: Implement database functionality to store the results of scans... possibly need another service to consume
#  this one. In that case return all output as Pandas DataFrames!
