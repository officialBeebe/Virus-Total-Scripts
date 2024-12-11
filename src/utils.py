import json
import os

import vt
from dotenv import dotenv_values
from vt.object import WhistleBlowerDict


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
