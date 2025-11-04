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


'''
SCRAPER:
constructor args:
list of webpages

scrape method:
returns list of dicts (list of headers)
'''
scraper = Scraper(None)
scraper.scrape()
