import json
from pprint import pprint
from typing import *

import inquirer
import vt
from dotenv import dotenv_values

# Constants
line_of_dashes = f"{"\n"}{"=" * 69}{"\n"}"
line_of_stars = f"{"\n"}{"*" * 69}{"\n"}"


def main(url="http://www.virustotal.com"):
    url_object = get_url_object(url)
    analysis_results = url_object.last_analysis_results
    analysis_stats = url_object.last_analysis_stats

    # Convert the URL object to a dictionary and pretty-print the entire url object... if the user wants to see it.
    should_print_url_object = inquirer.prompt([inquirer.Confirm("print_url_object", message="Print the URL object?")])
    if should_print_url_object[
        "print_url_object"] is True:  # should_print_url_object is a dictionary with a key "print_url_object" and a boolean value
        pprint(url_object.to_dict())

    print(line_of_dashes)

    # Print analysis results based on the categories selected by the user. See get_categories for inquirer package.
    analysis_categories = get_categories(message="Select categories to print: ", analysis_stats=analysis_stats)
    print_analysis_results_for(analysis_categories, analysis_results)


def get_categories(message, analysis_stats):
    print(f"Analysis stats: {analysis_stats}", end="\n\n")
    questions = [
        inquirer.Checkbox('analysis_categories',
                          message=message,
                          choices=["Malicious", "Suspicious", "Undetected", "Harmless", "Timeout"],
                          ),
    ]
    answers = inquirer.prompt(questions)
    return [category.lower() for category in
            answers["analysis_categories"]]  # List comprehension technique to lowercase each item in the list


def print_analysis_results_for(categories: List[str], analysis_results):
    """
    Print the analysis results for the specified categories
    :param categories:
    :param analysis_results:
    :return: Void
    """

    for i, category in enumerate(categories):
        print(f"Category: {category}", end="\n\n")
        for engine, result in analysis_results.items():
            if result["category"] == category:
                print(json.dumps(
                    {
                        "Engine": engine,
                        "Category": result["category"],
                        "Method": result["method"],
                        "Result": result["result"]
                    },
                    indent=6)
                )

        # Print a line of stars after each category except the last one
        if categories[i] != categories[-1]:
            print(line_of_stars)


def get_url_object(url):
    """
    Get the URL object for the specified URL
    :param url:
    :return: URL object
    """
    # Load the environment variables from the .env file
    config = dotenv_values("../.env")  # Returns a dictionary
    key = config["API_KEY"]  # "API_KEY" value from the dictionary
    if not key:
        raise ValueError("API_KEY not in .env file...")

    # TODO: Load the API key securely from a remote server, OR load a .env everytime?

    try:
        # Use context manager to establish a connection to the VirusTotal API, perform an action, and close the connection
        with vt.Client(key) as Client:
            url_id = vt.url_id(url)  # VirusTotal backend hashes the URL
            url_object = Client.get_object(f"/urls/{url_id}")

            return url_object


    except Exception as e:
        print(f"EXCEPTION: {e}")


if __name__ == "__main__":
    main(input("Enter a URL: "))
