import os
import math
import netlas
import json
from dotenv import load_dotenv
from cert_analyzer.netlas_parser import parse_netlas_result
from cert_analyzer.analysis.basic_analysis import analyze_netlas_result

load_dotenv()

def fetch_total_results(connection, query, datatype="cert"):
    """Get the total number of results for the query."""
    total = connection.count(query, datatype=datatype)
    return total.get("count", 0)


def fetch_page_results(connection, query, page, datatype="cert"):
    """Request one page of results."""
    return connection.search(query, datatype=datatype, page=page)


def main():
    searching_domain = "aau.dk"
    api_key = os.getenv("NETLAS_API_KEY")

    if not api_key:
        raise EnvironmentError("NETLAS_API_KEY is not set in the environment variables.")

    query = f"certificate.subject_dn:{searching_domain}"
    connection = netlas.Netlas(api_key)

    total = fetch_total_results(connection, query)
    if total == 0:
        print("No results found.")
        return

    results_per_page = 20
    total_pages = math.ceil(total / results_per_page)

    print(f"Total results: {total}")
    print(f"Total pages: {total_pages}")

    for page in range(total_pages):
        print(f"Fetching page {page + 1}/{total_pages}...")
        try:
            raw_results = fetch_page_results(connection, query, page)
            parsed = parse_netlas_result(raw_results, searching_domain)
            analyze_netlas_result(parsed)
        except Exception as e:
            print(f"Error while processing page {page + 1}: {e}")


if __name__ == "__main__":
    main()






# import netlas
# import os
# import json
# from dotenv import load_dotenv

# from cert_analyzer.netlas_parser import parse_netlas_result
# from cert_analyzer.analysis.basic_analysis import analyze_netlas_result

# import math


# load_dotenv()



# ## python3 -m cert_analyzer.main

# if __name__ == "__main__":
#     searching_domain = "aau.dk"
#     API_KEY = os.getenv("NETLAS_API_KEY")
#     query = f"certificate.subject_dn:{searching_domain}"

#     netlas_connection = netlas.Netlas(API_KEY)

#     page = 0
#     results_per_page = 20

#     # Get total count ONCE before the loop
#     total_results = netlas_connection.count(query, datatype="cert")
#     count_value = total_results['count']
#     total_pages = math.ceil(count_value / results_per_page)

#     print(f"Total results: {count_value}")
#     print(f"Total pages: {total_pages}")

#     while page < total_pages:
#         print(f"Fetching page {page + 1}/{total_pages}...")
        
#         raw_results = netlas_connection.search(query, datatype="cert", page=page)
        
#         netlas_result = parse_netlas_result(raw_results, searching_domain)
#         analyze_netlas_result(netlas_result)
        
#         page += 1

 


# # if __name__ == "__main__":


# #     searching_domain = "aau.dk"
# #     API_KEY = os.getenv("NETLAS_API_KEY")
# #     query = f"certificate.subject_dn:{searching_domain}"

# #     netlas_connection = netlas.Netlas(API_KEY)
# #     raw_results = netlas_connection.search(query, datatype="cert", page=5)

# #     netlas_result = parse_netlas_result(raw_results, searching_domain)

# #     analyze_netlas_result(netlas_result)










    
#     # API_KEY = os.getenv("NETLAS_API_KEY")   
#     # query = "certificate.subject_dn:aau.dk"

#     # netlas_connection = netlas.Netlas(API_KEY)

#     # search_results = netlas_connection.search(
#     #     query, datatype="cert"
#     # )

#     # # Save results to a JSON file
#     # with open("results.json", "w") as f:
#     #     json.dump(search_results, f, indent=4)

#     # print("Results saved to results.json")