import json
from csv import DictReader, DictWriter
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


#webpages_df = pd.read_csv("AUU_projekt.csv")
cnt = 0

with open("AUU_projekt.csv", 'r', encoding="utf8") as f:
    dict_reader = DictReader(f)
    dict_list = list(dict_reader)
    
'''
put csv entry (row) into json/dict done
get domain name from dict key domæne
check crt.sh for this domain name
put response into field in dict that contains cert info
put dict into array
'''

fields_list = list(dict_list[0].keys())
fields_list.append("Certifikat")

cert_dict_list = []

with open("blocked_with_certs.csv", 'a', encoding="utf8", newline='') as csvfile:
    fieldnames = fields_list
    writer = DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()    
    
    for row in dict_list:
        # status report
        if cnt % 100 == 0:
            print(cnt)
            writer.writerows(cert_dict_list)
            cert_dict_list = []
        cnt += 1

        
        # search crt.sh for current domain
        res = json.dumps(crtshAPI().search(row["Domæne"]))
        # create dict copying fields from row
        temp_dict = {**row}

        # there is a cert, add it to the field. otherwise add an empty array for now
        # the placecholder empty value should be something else
        # when domains didn't have a cert on crt, it usually just returned an empty array
        # a few of them did return "null" though
        # i really do not like the solution below, but dont really care about
        # figuring it completely out
        if res == "[]":
            continue

        temp_dict["Certifikat"] = res

        cert_dict_list.append(temp_dict)

'''
SCRAPER:
constructor args:
list of webpages

scrape method:
returns list of dicts (list of headers)
'''
#scraper = Scraper(webpages_list)
#scraper.scrape()
