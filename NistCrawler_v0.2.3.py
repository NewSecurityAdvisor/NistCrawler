import requests
from bs4 import BeautifulSoup
import urllib.parse
import argparse
import math
import csv
import os

# Function to scrape NIST CVE database
def scrape_nist_cve(cpe_query):
    # URL encode the CPE query
    encoded_query = urllib.parse.quote(cpe_query)
    base_url = "https://nvd.nist.gov/vuln/search/results"
    
    all_vulns = []
    results_per_page = 20

    # Initial request to find the total number of matching records
    full_url = f"{base_url}?adv_search=true&isCpeNameSearch=true&query={encoded_query}&startIndex=0"
    response = requests.get(full_url)

    if response.status_code != 200:
        print(f"Failed to retrieve data from NIST (Status Code: {response.status_code})")
        return

    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract total number of matching records
    total_vulns = soup.find("strong", {"data-testid": "vuln-matching-records-count"})
    if not total_vulns:
        print("No matching records found.")
        return
    
    # Remove commas from the total_vulns string before converting it to an integer
    total_vulns = int(total_vulns.get_text(strip=True).replace(",", ""))
    print(f"Total vulnerabilities found: {total_vulns}")

    # Calculate the number of pages
    num_pages = math.ceil(total_vulns / results_per_page)

    # Iterate through each page of results
    for page in range(num_pages):
        start_index = page * results_per_page
        full_url = f"{base_url}?adv_search=true&isCpeNameSearch=true&query={encoded_query}&startIndex={start_index}"
        response = requests.get(full_url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract CVE information
        cve_table = soup.find("table", {"data-testid": "vuln-results-table"})
        if not cve_table:
            print(f"No CVE results found on page {page + 1}.")
            continue

        # Iterate over each row up to 20 rows (from vuln-row-0 to vuln-row-19)
        for row in range(20):
            vuln_row = cve_table.find("tr", {"data-testid": f"vuln-row-{row}"})
            if not vuln_row:
                continue

            try:
                # Extract the CVE number and URL from the first column
                cve_link = vuln_row.find("a", {"data-testid": f"vuln-detail-link-{row}"})
                cve_number = cve_link.get_text(strip=True) if cve_link else "N/A"
                cve_url = f"https://nvd.nist.gov{cve_link['href']}" if cve_link else "N/A"

                # Description in the second column
                description = vuln_row.find("p", {"data-testid": f"vuln-summary-{row}"}).get_text(strip=True)
                
                # CVSS V3.1 score in the third column (if available)
                score_column = vuln_row.find("span", {"id": "cvss3-link"})
                score_v3 = None
                if score_column and "V3.1:" in score_column.get_text(strip=True):
                    score_v3 = float(score_column.get_text(strip=True).split("V3.1:")[1].split()[0])

                # Published date extracted from the summary paragraph
                published_date = vuln_row.find("span", {"data-testid": f"vuln-published-on-{row}"}).get_text(strip=True) if vuln_row.find("span", {"data-testid": f"vuln-published-on-{row}"}) else "N/A"

                # Add the data to the list of vulnerabilities if CVSS V3.1 score exists
                if score_v3:
                    all_vulns.append({
                        'cve_number': cve_number,
                        'score': score_v3,
                        'description': description,
                        'published_date': published_date,
                        'url': cve_url
                    })

            except (IndexError, ValueError, AttributeError) as e:
                print(f"Error processing row: {e}")
                continue

    # Sort the vulnerabilities by CVSS V3.1 score in descending order
    all_vulns.sort(key=lambda x: x['score'], reverse=True)

        # Print the sorted vulnerabilities in table format
    print(f"\n{'CVE Number':<20} {'Score':<8} {'Description':<100} {'Published Date':<20} {'URL'}")
    print("=" * 180)
    for vuln in all_vulns:
        # Truncate description to 95 characters and append "..." if truncated
        truncated_desc = vuln['description'][:95] + "..." if len(vuln['description']) > 95 else vuln['description']
        
        # Determine color based on the CVSS score
        if vuln['score'] >= 7.0:
            color = "\033[91m"  # Red for high severity
        elif vuln['score'] >= 4.0:
            color = "\033[93m"  # Yellow for medium severity
        else:
            color = "\033[92m"  # Green for low severity
            
        # Print formatted output with colored CVSS score
        print(f"{vuln['cve_number']:<20} {color}{vuln['score']:<8}\033[0m {truncated_desc:<100} {vuln['published_date']:<20} {vuln['url']}")


    output_to_csv(all_vulns, cpe_query)

# Function to output vulnerabilities to a CSV file
def output_to_csv(vulns, cpe_query):
    # Create output directory if it doesn't exist
    output_dir = './NistSearchResults'
    os.makedirs(output_dir, exist_ok=True)

    # Create a human-readable filename
    filename = f'{output_dir}/nist_cve_results_{cpe_query.replace(":", "_")}.csv'
    
    # Create and write to CSV file
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['cve_number', 'score', 'description', 'published_date', 'url']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for vuln in vulns:
            writer.writerow(vuln)

    print(f"\nResults have been written to '{filename}'.")

# Command-line argument parsing
def main():
    parser = argparse.ArgumentParser(description='NIST CVE Scraper')
    parser.add_argument('cpe_query', type=str, help='CPE search query (e.g., "cpe:2.3:o:microsoft:windows")')
    
    # Parse the command-line arguments
    args = parser.parse_args()

    # Call the scraping function with the provided CPE query
    scrape_nist_cve(args.cpe_query)

if __name__ == "__main__":
    main()

