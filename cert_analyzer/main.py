import os
import math
from pathlib import Path
import netlas
import json
from dataclasses import asdict
from dotenv import load_dotenv
import time,csv
from cert_analyzer.netlas_parser import parse_netlas_result
from cert_analyzer.analysis.basic_analysis import analyze_netlas_result
from cert_analyzer.load_excel_domains import get_blocked_domains

## RUN: python3 -m cert_analyzer.main

load_dotenv()

def fetch_total_results(connection, query, datatype="cert"):
    """Get the total number of results for the query."""
    total = connection.count(query, datatype=datatype)
    return total.get("count", 0)


def fetch_page_results(connection, query, page, datatype="cert"):
    """Request one page of results."""
    return connection.search(query, datatype=datatype, page=page)


def get_netlas_client() -> netlas.Netlas:
    """Create and return an authenticated Netlas client using NETLAS_API_KEY."""
    api_key = os.getenv("NETLAS_API_KEY")
    if not api_key:
        raise EnvironmentError("NETLAS_API_KEY is not set in the environment variables.")
    return netlas.Netlas(api_key)


def build_certificate_query(domain: str) -> str:
    """Build the Netlas search query for certificates matching a domain."""
    return f"certificate.subject_dn:{domain}"


def fetch_all_certificate_results(domain: str, results_per_page: int = 20):
    """
    Generator that yields parsed certificate results for all pages
    of a Netlas search for the given domain.
    """
    client = get_netlas_client()
    query = build_certificate_query(domain)

    total_results = fetch_total_results(client, query)
    if total_results == 0:
        print(f"No results found for domain: {domain}")
        return

    MAX_PAGES = 30
    total_pages = math.ceil(total_results / results_per_page)
    print(f"Total results: {total_results}")
    print(f"Total pages: {total_pages}")

    if total_pages > MAX_PAGES:
        print(f"Warning: Limiting to first {MAX_PAGES} pages out of {total_pages} total pages.")
        total_pages = MAX_PAGES

    for page_index in range(total_pages):
        print(f"Fetching page {page_index + 1}/{total_pages}...")

        retries = 0
        max_retries = 5

        while True:
            try:
                raw_page = fetch_page_results(client, query, page_index)
                parsed_page = parse_netlas_result(raw_page, domain)
                yield parsed_page
                break  

            except Exception as exc:
                retries += 1
                print(f"❌ Error on page {page_index + 1}: {exc}")

                if retries >= max_retries:
                    print(f"⚠️ Max retries reached for page {page_index + 1}. Skipping.")
                    break

                print("🔄 Waiting 60 seconds before retrying...")
                time.sleep(60) 





def save_certificates_of_a_domain_in_json(domain: str, certificates: list, output_folder: str = "certs"):
    os.makedirs(output_folder, exist_ok=True)

    # Flatten certs and insert domain field
    all_rows = []
    for cert in certificates:
        row = asdict(cert)
        row["domain"] = domain
        all_rows.append(row)

    out_path = f"{output_folder}/{domain}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        # indent for pretty-print; remove indent=2 if you want compact
        json.dump(all_rows, f, indent=2, ensure_ascii=False)

    if not all_rows:
        print(f"No certificates for {domain} - saved empty array []")
    else:
        print(f"Saved {len(all_rows)} certificates for {domain} to {out_path}")








def extract_and_analyze_certificates(searching_domain: str):
    """Fetch, analyze, and return all certificates for a domain."""
    all_certs = []
    
    for parsed_page in fetch_all_certificate_results(searching_domain):
        analyze_netlas_result(parsed_page)
        all_certs.extend(parsed_page.items)  # Collect certificates from NetlasResult
    
    return all_certs


def keep_the_latest_certificate(certificates: list):
    """
    Keep only the certificate with the most recent end date.
    Returns the most recent certificate or None if the list is empty.
    """
    if not certificates:
        return None
    
    most_recent = None
    latest_end_date = None

    for cert in certificates:
        try:
            end_date = cert.validity.end
            if latest_end_date is None or end_date > latest_end_date:
                latest_end_date = end_date
                most_recent_certificate = cert
        except Exception as e:
            print(f"Error processing certificate for latest date: {e}")
            continue

    return most_recent_certificate


def main():
    blocked_domains = get_blocked_domains()
    for domain in blocked_domains[69:]:
        print(f"\nProcessing domain: {domain}")
        certificates = extract_and_analyze_certificates(domain)
        save_certificates_of_a_domain_in_json(domain, certificates)







    


if __name__ == "__main__":
    main()




