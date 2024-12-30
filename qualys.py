# For Creation of the Qualys Report
import os
import pandas as pd
from datetime import datetime


def identify_and_rename_csv_files(folder_path):
    csv_files = [f for f in os.listdir(folder_path) if f.endswith('.csv')]

    for file in csv_files:
        file_path = os.path.join(folder_path, file)
        with open(file_path, 'r', encoding='utf-8') as f:
            data = f.readlines()

        if len(data) >= 8:
            header_row_8 = data[7].strip().split(',')
            if len(header_row_8) == 28:  # Matches A8 to AB8
                new_file_path = os.path.join(folder_path, 'IT_OPS_Undated.csv')
                os.replace(file_path, new_file_path)
                print(f"Renamed {file} to IT_OPS_Undated.csv")

        if len(data) >= 11:
            header_row_11 = data[10].strip().split(',')
            if len(header_row_11) == 42:  # Matches A11 to AP11
                new_file_path = os.path.join(folder_path, 'IT_OPS_Dated.csv')
                os.replace(file_path, new_file_path)
                print(f"Renamed {file} to IT_OPS_Dated.csv")


def process_it_ops_files(folder_path, server_owners_file):
    # Process IT_OPS_Undated.csv
    undated_file = os.path.join(folder_path, 'IT_OPS_Undated.csv')
    undated_df = pd.read_csv(undated_file, skiprows=7)
    owners_df = pd.read_csv(server_owners_file)

    # Add Owner column
    merged_df = undated_df.merge(owners_df, how='left', left_on='IP', right_on='IP Address')
    merged_df.drop(columns=['IP Address'], inplace=True)
    merged_df.insert(merged_df.columns.get_loc('IP') + 1, 'Owner', merged_df.pop('Owner'))

    # Add Unique Id
    merged_df['Unique Id'] = merged_df['IP'] + merged_df['QID'].fillna(0).astype(int).astype(str)
    port_index = merged_df.columns.get_loc('Port')
    merged_df.insert(port_index, 'Unique Id', merged_df.pop('Unique Id'))

    # Add First Detected
    dated_file = os.path.join(folder_path, 'IT_OPS_Dated.csv')
    dated_df = pd.read_csv(dated_file, skiprows=10)

    # Ensure Unique Ids in Dated file are unique to prevent multiplication in merge
    dated_df['Unique Id'] = dated_df['IP'] + dated_df['QID'].fillna(0).astype(int).astype(str)
    dated_df = dated_df.drop_duplicates(subset=['Unique Id'])

    dated_subset = dated_df[['Unique Id', 'First Detected']]

    # Merge IT_OPS_Undated with IT_OPS_Dated based on 'Unique Id'
    merged_df = pd.merge(merged_df, dated_subset, on='Unique Id', how='left')

    # Convert First Detected to desired format
    merged_df['First Detected'] = pd.to_datetime(merged_df['First Detected']).dt.strftime('%m/%d/%Y %H:%M:%S')

    # Add Days column
    current_time = datetime.now()
    merged_df['Days'] = merged_df['First Detected'].apply(
        lambda x: (current_time - datetime.strptime(x, '%m/%d/%Y %H:%M:%S')).days
        if pd.notnull(x) else None
    ).astype('Int64')

    # Add Vulnerability Id column
    def parse_vulnerability(title):
        if not isinstance(title, str):
            return "Others"
        vulnerability_mapping = {
            'SMB': 'SMB',
            'SNMP': 'SNMP',
            'Chrome': 'Chrome',
            'Foxit': 'Foxit',
            'Mozilla': 'Mozilla Firefox',
            'Adobe': 'Adobe',
            'TLS': 'TLS-Cipher',
            '7-Zip': '7-Zip',
            'Explorer': 'Internet Explorer'
        }
        for keyword, value in vulnerability_mapping.items():
            if keyword in title:
                return value
        return "Others"

    merged_df['Vulnerability Id'] = merged_df['Title'].apply(parse_vulnerability)
    type_index = merged_df.columns.get_loc('Type')
    merged_df.insert(type_index + 1, 'Vulnerability Id', merged_df.pop('Vulnerability Id'))

    # Add Status column based on Severity and Days
    def determine_status(row):
        # Check if Severity or Days is missing (NA)
        if pd.isna(row['Severity']) or pd.isna(row['Days']):
            return 'Not Overdue'  # If either value is missing, we can consider it as 'Not Overdue'

        if row['Severity'] == 3 and row['Days'] > 90:
            return 'Overdue'
        elif row['Severity'] == 4 and row['Days'] > 60:
            return 'Overdue'
        elif row['Severity'] == 5 and row['Days'] > 30:
            return 'Overdue'
        return 'Not Overdue'

    # Add Severity Tag column based on Severity Value
    def determine_severity_tag(row):
        if row['Severity'] == 3:
            return 'Medium'
        elif row['Severity'] == 4:
            return 'High'
        elif row['Severity'] == 5:
            return 'Critical'


    merged_df['Severity Tag'] = merged_df.apply(determine_severity_tag, axis=1)

    # Insert Severity Tag column after Severity Column
    severity_index = merged_df.columns.get_loc('Severity')
    merged_df.insert(severity_index + 1, 'Severity Tag', merged_df.pop('Severity Tag'))


    merged_df['Status'] = merged_df.apply(determine_status, axis=1)

    # Insert Status column after Severity Tag column
    severity_index = merged_df.columns.get_loc('Severity Tag')
    merged_df.insert(severity_index + 1, 'Status', merged_df.pop('Status'))

    # Add Vulnerability Description column
    merged_df['Vulnerability Description'] = merged_df['Threat'] + " " + merged_df['Impact']

    # Insert Vulnerability Description column after Vulnerability Id
    vulnerability_id_index = merged_df.columns.get_loc('Vulnerability Id')
    merged_df.insert(vulnerability_id_index + 1, 'Vulnerability Description',
                     merged_df.pop('Vulnerability Description'))

    # Save updated file - IT_OPS_Undated_plus.csv should match row count of IT_OPS_Undated.csv
    merged_df.to_csv(os.path.join(folder_path, 'IT_OPS_Undated_plus.csv'), index=False)
    print("Processed IT_OPS_Undated.csv -> IT_OPS_Undated_plus.csv")

    # Process IT_OPS_Dated.csv
    dated_df['QID'] = pd.to_numeric(dated_df['QID'], errors='coerce').fillna(0).astype(int).astype(str)
    dated_df['Unique Id'] = dated_df['IP'] + dated_df['QID']
    port_index = dated_df.columns.get_loc('Port')
    dated_df.insert(port_index, 'Unique Id', dated_df.pop('Unique Id'))

    # Prevent duplication in Dated file
    dated_df = dated_df.drop_duplicates(subset=['Unique Id'], keep='first')

    # Save updated file - IT_OPS_Dated_plus.csv
    dated_df.to_csv(os.path.join(folder_path, 'IT_OPS_Dated_plus.csv'), index=False)
    print("Processed IT_OPS_Dated.csv -> IT_OPS_Dated_plus.csv")


# Main execution
folder_path = "C://Users//Joe//Documents//Codes//Python//IT Operations - Infrastructure//Qualys_files"
server_owners_file = 'Server Owners.csv'

identify_and_rename_csv_files(folder_path)
process_it_ops_files(folder_path, server_owners_file)
