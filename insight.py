# Creation of the Insight VM Report
import os
import csv
import pandas as pd
from datetime import datetime

def merge_csv_files_in_folder(folder_path, output_file_name):
    """
    Merges two CSV files in a specified folder with identical column headers into a single CSV file using the csv library.
    """
    # List all CSV files in the folder
    csv_files = [f for f in os.listdir(folder_path) if f.endswith('.csv')]

    # Ensure there are exactly three CSV files in the folder
    if len(csv_files) != 3:
        raise ValueError(f"Expected exactly 3 CSV files in the folder, but found {len(csv_files)}.")

    file1_path = os.path.join(folder_path, csv_files[0])
    file2_path = os.path.join(folder_path, csv_files[1])
    file3_path = os.path.join(folder_path, csv_files[2])

    try:
        with open(file1_path, mode='r', newline='', encoding='utf-8') as file1, \
                open(file2_path, mode='r', newline='', encoding='utf-8') as file2, \
                open(file3_path, mode='r', newline='', encoding='utf-8') as file3, \
                open(os.path.join(folder_path, output_file_name), mode='w', newline='',
                     encoding='utf-8') as output_file:

            reader1 = csv.reader(file1)
            reader2 = csv.reader(file2)
            reader3 = csv.reader(file3)
            writer = csv.writer(output_file)

            # Read headers
            headers1 = next(reader1)
            headers2 = next(reader2)

            if headers1 != headers2:
                raise ValueError("The column headers in the two files do not match!")

            # Write header to the output file
            writer.writerow(headers1)

            # Write rows from the 3 files
            writer.writerows(reader1)
            writer.writerows(reader2)
            writer.writerows(reader3)

        print(f"Merged file saved as: {os.path.join(folder_path, output_file_name)}")

    except Exception as e:
        raise ValueError(f"Error merging CSV files: {e}")


def enrich_merged_file(merged_file_path, owners_file_path, output_file_path):
    try:
        # Load merged CSV
        merged_df = pd.read_csv(merged_file_path)

        # Ensure the Vulnerable Since column exists
        if 'Vulnerable Since' not in merged_df.columns:
            raise ValueError("'Vulnerable Since' column not found in merged file.")

        # Check for missing values in 'Vulnerable Since' and fill them with a placeholder (e.g., "Unknown Date")
        merged_df['Vulnerable Since'].fillna('Unknown Date', inplace=True)

        # Calculate the Days column based on 'Vulnerable Since'
        today = pd.Timestamp(datetime.now())

        # Create a mask for valid dates in 'Vulnerable Since'
        valid_dates = pd.to_datetime(merged_df['Vulnerable Since'], errors='coerce')
        merged_df['Days'] = (today - valid_dates).dt.days

        # Insert Days column right after Vulnerable Since
        vuln_since_index = merged_df.columns.get_loc('Vulnerable Since')
        merged_df.insert(vuln_since_index + 1, 'Days', merged_df.pop('Days'))

        # Load Server_Owners.csv
        owners_df = pd.read_csv(owners_file_path)

        # Ensure the necessary columns exist
        if 'IP Address' not in owners_df.columns or 'Owner' not in owners_df.columns:
            raise ValueError("'Server_Owners.csv' must contain 'IP Address' and 'Owner' columns.")

        if 'Asset IP Address' not in merged_df.columns:
            raise ValueError("'Insight_Merged.csv' must contain 'Asset IP Address' column.")

        # Create a mapping of IP Address to Owner
        owners_mapping = dict(zip(owners_df['IP Address'], owners_df['Owner']))

        # Add the Owner column to the merged dataframe
        merged_df['Owner'] = merged_df['Asset IP Address'].map(owners_mapping).fillna('Not Available')

        # Insert the Owner column right after Asset IP Address
        asset_ip_index = merged_df.columns.get_loc('Asset IP Address')
        merged_df.insert(asset_ip_index + 1, 'Owner', merged_df.pop('Owner'))

        # Add the Severity Tag column
        if 'Vulnerability CVSS Score' not in merged_df.columns:
            raise ValueError("'Vulnerability CVSS Score' column not found in merged file.")

        def severity_tag(score):
            if 9.0 <= score <= 10.0:
                return 'Critical'
            elif 7.0 <= score <= 8.9:
                return 'High'
            elif 4.0 <= score <= 6.9:
                return 'Medium'
            elif 0.1 <= score <= 3.9:
                return 'Low'
            elif score == 0.0:
                return 'None'
            return 'None'

        merged_df['Vulnerability CVSS Score'] = pd.to_numeric(
            merged_df['Vulnerability CVSS Score'], errors='coerce'
        )
        merged_df['Severity Tag'] = merged_df['Vulnerability CVSS Score'].apply(severity_tag)

        # Insert Severity Tag column right after Vulnerability CVSS Score
        score_index = merged_df.columns.get_loc('Vulnerability CVSS Score')
        merged_df.insert(score_index + 1, 'Severity Tag', merged_df.pop('Severity Tag'))

        # Add the Status column
        def status(severity, days):
            if severity == 'Medium' and days > 90:
                return 'Overdue'
            elif severity == 'High' and days > 60:
                return 'Overdue'
            elif severity == 'Critical' and days > 30:
                return 'Overdue'
            return 'Not Overdue'

        merged_df['Status'] = merged_df.apply(
            lambda row: status(row['Severity Tag'], row['Days']), axis=1
        )

        # Save the updated dataframe to a new CSV file
        merged_df.to_csv(output_file_path, index=False, encoding='utf-8')
        print(f"Enriched file saved as: {output_file_path}")

    except Exception as e:
        raise ValueError(f"Error processing merged file: {e}")


# Example usage
folder_path = "C://Users//Joe//Documents//Codes//Python//IT Operations - Infrastructure//Insight_files"
owners_file_path = "C://Users//Joe//Documents//Codes//Python//IT Operations - Infrastructure//Server Owners.csv"
merged_file_name = "Insight_Merged.csv"
final_output_file_name = "Insight_Enriched.csv"

# Merge the files
merge_csv_files_in_folder(folder_path, merged_file_name)

# Enrich the merged file
enrich_merged_file(
    merged_file_path=os.path.join(folder_path, merged_file_name),
    owners_file_path=owners_file_path,
    output_file_path=os.path.join(folder_path, final_output_file_name)
)
