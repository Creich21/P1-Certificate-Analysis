import json
from scraper import Scraper

'''
    TODO:
    append header information to "original" dataset
    save somewhere (easy to do)
'''

# load json into python
def parse_json(file):
    json_list = json.load(file)
    return json_list

# create array of domains
# CHANGE KEY WHEN IS KNOWN
def fetch_domains(json_list):
    domain_list = [d["domain"] for d in json_list]
    return domain_list

#
def add_headers(headers_list, original_dataset):
    # lookup table (dict)
    headers_lookup = {h['domain']: h['headers'] for h in headers_list]}

    merged = []

    for entry in original_dataset:
        # CHANGE KEY BELOW
        domain = entry['domain']
        # check if domain is in scraped dicts
        if domain in headers_lookup:
            # create new dict with all fields from og entry, add headers
            combined_dict = {**entry, 'headers':headers_lookup[domain])}
            merged.append(combined_dict)
        else:
            # if no entry in lookup table, create one with empty value
            merged.append({**entry, 'headers': None})
            
    return merged        

'''
SCRAPER:
constructor args:
list of webpages

scrape method:
returns list of dicts (list of headers)
'''
scraper = Scraper(None)
scraper.scrape()
