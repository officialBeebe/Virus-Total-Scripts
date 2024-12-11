import argparse
from pprint import pprint

import VirusTotalAPI
import utils as utils


def main(args=None, vt=None):
    # Get the API key from somewhere lol
    api_key = utils.get_api_key()
    vtapi = VirusTotalAPI.VirusTotalAPI(api_key)  # Instantiate the VirusTotalAPI object

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

    # Args controller
    if not key:
        raise ValueError(
            "This program requires an API key to run. Get one from https://www.virustotal.com/gui/join-us\n\nIf you have a key, enter the flag --key followed by your key.")

    if url:
        url_object = utils.get_url_object(url, key)
        analysis_results = url_object.last_analysis_results
        analysis_stats = url_object.last_analysis_stats

        if debug:
            pprint(url_object.to_dict())

        if output:
            utils.output_analysis_results(analysis_results)


if __name__ == "__main__":
    main()

# TODO: Implement fzf interface for selecting objects in the file system to scan. Also add object scanning
#  functionality...

# TODO: Implement argparse for command-line arguments to specify scanning a single URL, many URLS, or a file system
#  object or collection of objects.

# TODO: Implement database functionality to store the results of scans... possibly need another service to consume
#  this one. In that case return all output as Pandas DataFrames!
