from pprint import pprint

import vt
from dotenv import dotenv_values


def main():
    # Load the environment variables from the .env file
    config = dotenv_values("../.env")  # Returns a dictionary
    key = config["API_KEY"]  # "API_KEY" value from the dictionary
    if not key:
        raise ValueError("API_KEY not in .env file...")

    # TODO: Load the API key securely from a remote server, OR load a .env everytime?

    try:
        # Use context manager to establish a connection to the VirusTotal API, perform an action, and close the connection
        with vt.Client(key) as Client:
            url_id = vt.url_id("http://www.virustotal.com")  # VirusTotal backend hashes the URL
            url_object = Client.get_object("/urls/{}", url_id)

            pretty_url_object = dict(url_object.to_dict())
            pprint(pretty_url_object)


    except Exception as e:
        print(f"EXCEPTION: {e}")


if __name__ == "__main__":
    main()
