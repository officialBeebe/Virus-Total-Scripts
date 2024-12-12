import json

from vt.object import WhistleBlowerDict


def extract_report_summary(self, report_data):
    attributes = report_data.get('data', {}).get('attributes', {})
    summary = {
        "Reputation": attributes.get("reputation", "Unknown"),
        "Total Votes (Harmless/Malicious)": attributes.get("total_votes", {}),
        "Analysis Stats": attributes.get("last_analysis_stats", {}),
        "Categories": attributes.get("categories", {}),
        "Certificate Subject": attributes.get("last_https_certificate", {}).get("subject", {}).get("CN", "Unknown"),
        "Certificate Validity": attributes.get("last_https_certificate", {}).get("validity", {}),
        "DNS Records": attributes.get("last_dns_records", []),
        "Popularity Ranks": attributes.get("popularity_ranks", {}),
        "Creation Date": attributes.get("creation_date", "Unknown"),
        "WHOIS Info": attributes.get("whois", "Unknown")
    }
    return summary


def display_report_as_table(self, report_data):
    # Flatten the dictionary into a table-friendly format
    flat_data = [{"Attribute": key, "Value": value} for key, value in report_data.items()]
    df = pd.DataFrame(flat_data)  # Create DataFrame from the flattened data
    print(df.to_markdown(index=False))  # Display as a Markdown table


def transform_results(self, results):
    return [{"engine_name": engine_name, **details} for engine_name, details in results.items()]


def custom_serializer(self, obj):
    if isinstance(obj, WhistleBlowerDict):
        return dict(obj)  # Convert WhistleBlowerDict to standard dict
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def output_analysis_results(self, results):
    # print("DEBUG: Results received:", results)
    category_order = {
        "malicious": 0,
        "suspicious": 1,
        "undetected": 2,
        "harmless": 3,
        "timeout": 4
    }

    transformed_results = self.transform_results(results)

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
