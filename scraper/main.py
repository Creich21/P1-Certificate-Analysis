import json
import pandas as pd
from scraper import Scraper
from crtsh import crtshAPI

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
    headers_lookup = {h['domain']: h['headers'] for h in headers_list}

    merged = []

    for entry in original_dataset:
        # CHANGE KEY BELOW
        domain = entry['domain']
        # check if domain is in scraped dicts
        if domain in headers_lookup:
            # create new dict with all fields from og entry, add headers
            combined_dict = {**entry, 'headers':headers_lookup[domain]}
            merged.append(combined_dict)
        else:
            # if no entry in lookup table, create one with empty value
            merged.append({**entry, 'headers': None})
            
    return merged        


dict_list = []
webpages_df = pd.read_csv("AUU_projekt.csv")
#index 2 = urls
cnt = 0

'''
put csv entry (row) into json/dict
get domain name from dict
check crt.sh for this domain name
put response into field in dict that contains cert info
put dict into array
'''

for row in webpages_df.itertuples(index=false, name=None):
    temp_dict = row.to_dict()

    
    if cnt % 10000 == 0:
        print(cnt)
    cnt += 1

print(json.dumps(crtshAPI().search('')))


'''
SCRAPER:
constructor args:
list of webpages

scrape method:
returns list of dicts (list of headers)
'''
#scraper = Scraper(webpages_list)
#scraper.scrape()
