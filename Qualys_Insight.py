# Merging the Insight and Qualys Report together
import csv
from datetime import datetime


def merge_csv_files():
    # Input file paths
    it_ops_file = "C://Users//Joe//Documents//Codes//Python//IT Operations - Infrastructure//Qualys_files//IT_OPS_Undated_plus.csv"
    insight_file = "C://Users//Joe//Documents//Codes//Python//IT Operations - Infrastructure//Insight_files//Insight_Enriched.csv"

    # Output file path
    date_str = datetime.now().strftime("%d%b%y").upper()
    output_file = f"Qualys_Insight_Merged_{date_str}.csv"

    # Define output headers
    output_headers = [
        "Asset Names", "Asset IP Address", "Owner", "OS", "Asset OS Version",
        "Vulnerability Title", "Vulnerability Description", "Severity Tag",
        "Vulnerability ID", "Vulnerability CVE IDs", "Vulnerability Solution",
        "Vulnerability Proof", "Vulnerable Since", "Days", "Status", "Service Port"
    ]

    # Define column mappings for IT_OPS_Undated_plus.csv
    it_ops_columns = {
        "Asset Names": "DNS",
        "Asset IP Address": "IP",
        "Owner": "Owner",
        "OS": "OS",
        # "Asset OS Version": Not applicable in IT_OPS_Undated_plus.csv
        "Vulnerability Title": "Title",
        "Vulnerability Description": "Vulnerability Description",
        "Severity Tag": "Severity Tag",
        "Vulnerability ID": "Vulnerability Id",
        "Vulnerability CVE IDs": "CVE ID",
        "Vulnerability Solution": "Solution",
        "Vulnerability Proof": "Results",
        "Vulnerable Since": "First Detected",
        "Days": "Days",
        "Status": "Status",
        "Service Port": "Port"
    }

    # Define column mappings for Insight_Enriched.csv
    insight_columns = {
        "Asset Names": "Asset Names",
        "Asset IP Address": "Asset IP Address",
        "Owner": "Owner",
        "OS": "Asset OS Name",
        "Asset OS Version": "Asset OS Version",
        "Vulnerability Title": "Vulnerability Title",
        "Vulnerability Description": "Vulnerability Description",
        "Severity Tag": "Severity Tag",
        "Vulnerability ID": "Vulnerability ID",
        "Vulnerability CVE IDs": "Vulnerability CVE IDs",
        "Vulnerability Solution": "Vulnerability Solution",
        "Vulnerability Proof": "Vulnerability Proof",
        "Vulnerability Since": "Vulnerability Test Date",
        "Days": "Days",
        "Status": "Status",
        "Service Port": "Service Port"
    }

    # Open files and write output
    with open(it_ops_file, mode='r', newline='', encoding='utf-8') as it_ops, \
         open(insight_file, mode='r', newline='', encoding='utf-8') as insight, \
         open(output_file, mode='w', newline='', encoding='utf-8') as output:

        it_ops_reader = csv.DictReader(it_ops)
        insight_reader = csv.DictReader(insight)

        output_writer = csv.DictWriter(output, fieldnames=output_headers)
        output_writer.writeheader()

        # Write rows from IT_OPS_Undated_plus.csv
        for row in it_ops_reader:
            merged_row = {
                header: row.get(it_ops_columns.get(header, ''), '') for header in output_headers
            }
            output_writer.writerow(merged_row)

        # Write rows from Insight_Enriched.csv
        for row in insight_reader:
            merged_row = {
                header: row.get(insight_columns.get(header, ''), '') for header in output_headers
            }
            output_writer.writerow(merged_row)

    print(f"Merged file created: {output_file}")

if __name__ == "__main__":
    merge_csv_files()
