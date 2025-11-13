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

cnt = 1


with open("filtered_tranco_dataset.csv", 'r', encoding="utf8") as f:
    dict_reader = DictReader(f)
    dict_list = list(dict_reader)
    print(dict_list[0])
    
'''
put csv entry (row) into json/dict done
get domain name from dict key domæne
check crt.sh for this domain name
put response into field in dict that contains cert info
put dict into array
'''

fields_list = list(dict_list[0].keys())

cert_dict_list = []
no_cert_dict_list = []

no_certs_csv = open("popular_no_certs.csv", 'a', encoding="utf8", newline='')
with open("popular_with_certs.csv", 'a', encoding="utf8", newline='') as certs_csv:
    unblocked_writer = DictWriter(no_certs_csv, fieldnames=fields_list)
    fields_list.append("Certifikat")
    blocked_writer = DictWriter(certs_csv, fieldnames=fields_list)

    unblocked_writer.writeheader()
    blocked_writer.writeheader()    
    
    for row in dict_list:
        # status report
        if cnt % 100 == 0:
            print(cnt)
            blocked_writer.writerows(cert_dict_list)
            unblocked_writer.writerows(no_cert_dict_list)
            no_cert_dict_list = []
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
            no_cert_dict_list.append({**row})

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
