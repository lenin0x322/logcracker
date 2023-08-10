import os
import pandas as pd
import vt
import datetime
import base64
import argparse
import xlsxwriter
import sys
import time
import sys

import sys

def print_loading(percent_complete, ip):
    total_width = 50
    width = int(total_width * percent_complete / 100)
    loading_bar = "━" * width + " " * (total_width - width)
    
    # Choose colors based on percent_complete
    if percent_complete < 30:
        color_code = '\033[91m'  # Red
    elif percent_complete < 70:
        color_code = '\033[93m'  # Yellow
    else:
        color_code = '\033[92m'  # Green
    
    loading_format = f"\r{color_code}{loading_bar}\033[0m {percent_complete:.1f}% - {ip}"
    sys.stdout.write(loading_format + "\r")
    sys.stdout.flush()



def vt_data_enrich(ip):
    try:
        vt_json = client.get_json(f"/ip_addresses/{str(ip)}")['data']['attributes']['last_analysis_stats']
        vt_ratio = f"{vt_json['malicious'] + vt_json['suspicious']}/{sum(vt_json.values())}"
        
        if int(vt_json['malicious']) > 1:
            # print(f"https://virustotal.com/gui/ip-address/{ip} => {str(vt_json['malicious'])}")
            pass
        
        return vt_ratio
    except Exception as e:
        print("Error fetching VirusTotal data:", e)
        return None

# Get the args from the user
parser = argparse.ArgumentParser(description="Filter log files and perform VirusTotal enrichment.")
parser.add_argument("-s", "--search", help="Search string (case-insensitive) to filter lines.", type=str)
parser.add_argument('-m', "--method", help="Filter the request method (GET, POST, etc)", type=str)
args = parser.parse_args()

if not any(vars(args).values()):
    parser.print_help()
    print("Please provide the arguments.")
    exit(1)

# Get the current directory
current_directory = os.getcwd()

# List all files in the directory
files = os.listdir(current_directory)

# Define a function to check if a line has specific items
def search_function(line, args):
    if args.method:
        return args.search.lower() in line.lower() and args.method.lower() in line.lower()
    else:
        return args.search.lower() in line.lower()

# Create lists to store data for different columns
file_column = []
ip_column = []
date_column = []
request_column = []
method_column = []  # Add this for storing request methods
vt_ratio_column = []  # Add this for storing VirusTotal ratios

# Initialize VirusTotal client
bsf = 'ZTI1M2RkMTg0OTA2YjFmNzRlYWNmMjE4OTE2YTg5NmVlNWY5YzllZDkyMGU2OTExMDRmODE2YzFkYTgzNWMwYw=='
API_KEY = base64.b64decode(bsf).decode('utf-8')
client = vt.Client(API_KEY)

# Count the total number of unique IP addresses
unique_ips = set()

for file in files:
    full_path = os.path.join(current_directory, file)
    if file.endswith(('.py', '.ps1')) or not os.path.isfile(full_path):
        continue  # Skip Python and non-file entries
    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if search_function(line, args):
                parts = line.split()
                if len(parts) >= 7:
                    ip = parts[0]
                    unique_ips.add(ip)

total_unique_ips = len(unique_ips)
total_calls = total_unique_ips  # Total calls to make is the same as the total unique IPs

# Enrich and filter data from log files
counter = 0
completed_calls = 0  # Track completed API calls
start_time = datetime.datetime.now()
total_files = len(files)
print("Approx Duration:", str(datetime.timedelta(seconds=total_files)), "\n")

# Perform the VirusTotal API calls
for file in files:
    full_path = os.path.join(current_directory, file)
    if file.endswith(('.py', '.ps1')) or not os.path.isfile(full_path):
        continue  # Skip Python and non-file entries
    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if search_function(line, args):
                parts = line.split()
                if len(parts) >= 7:
                    ip = parts[0]
                    if ip not in ip_column:
                        vt_ratio = vt_data_enrich(ip)
                        if vt_ratio:
                            ip_column.append(ip)
                            date_column.append(parts[3][1:] + ' ' + parts[4][:-1])
                            request_column.append(parts[5] + ' ' + parts[6])
                            method_column.append(parts[5])  # Save request method
                            file_column.append(file)
                            vt_ratio_column.append(vt_ratio)  # Save VirusTotal ratio
                            counter += 1
                            completed_calls += 1
                            percent_complete = (completed_calls / total_calls) * 100
                            print_loading(percent_complete, ip)  # Modified line

                            # Check if all unique IPs have been processed
                            if completed_calls >= total_unique_ips:
                                print("\nLoading complete!")
                                break  # Exit the loop
        # Check if all unique IPs have been processed
        if completed_calls >= total_unique_ips:
            break  # Exit the loop

# Close VirusTotal client
client.close()

# Create a Pandas DataFrame from the collected data
data = {
    'File': file_column,
    'IP': ip_column,
    'Date': date_column,
    'Request': request_column,
    'Method': method_column,
    'VirusTotal_Ratio': vt_ratio_column
}
df = pd.DataFrame(data)

# Extract the detection count from VirusTotal_Ratio and convert to integer for sorting
df['Detection_Count'] = df['VirusTotal_Ratio'].apply(lambda x: int(x.split('/')[0]))

# Sort the DataFrame based on Detection_Count in descending order and keep the original order for equal counts
df.sort_values(by=['Detection_Count', 'VirusTotal_Ratio'], ascending=[False, False], inplace=True)

# Reset the index after sorting
df.reset_index(drop=True, inplace=True)

# Drop the Detection_Count column
df.drop(columns=['Detection_Count'], inplace=True)

# Calculate and display total duration
end_time = datetime.datetime.now()
duration = end_time - start_time



# Define the Excel filename
excel_filename = "filtered_powershell_data.xlsx"

# Create a Pandas Excel writer using XlsxWriter as the engine
with pd.ExcelWriter(excel_filename, engine='xlsxwriter') as excel_writer:
    # Convert the DataFrame to an XlsxWriter Excel object
    df.to_excel(excel_writer, index=False, sheet_name='Filtered_Data')

    # Get the xlsxwriter workbook and worksheet objects
    workbook = excel_writer.book
    worksheet = excel_writer.sheets['Filtered_Data']

    # Get the max column width for each column
    max_width = max([len(str(s)) for s in df.columns] + [max([len(str(s)) for s in df[col]]) for col in df.columns])
    for i, col in enumerate(df.columns):
        column_width = max(df[col].astype(str).apply(len).max(), len(col))
        worksheet.set_column(i, i, column_width + 2)

    # Add hyperlink formatting to IP column
    for i, ip in enumerate(ip_column, start=1):
        worksheet.write_url(i, 1, f"https://virustotal.com/gui/ip-address/{ip}", string=ip)

# Print fetched IPs and loading completion
print_loading(100, ip_column[-1])
print(f"\nFiltered PowerShell data saved to {excel_filename}")
print(f"Approx Duration: {duration}")
print(f"Total Virustotal api call: {completed_calls}")
