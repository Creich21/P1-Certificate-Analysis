import math
import netlas
import re
import tldextract
import requests
import time
import dns
import logging
import csv
import dns.resolver
from datetime import datetime


brands=["dankort", "dsv", "danskebank", "jyskebank", "nordea", "nordisk", "saxo", "seb", "sydbank", "vestergaard", "santanderconsumer", "sparnord", "nemid",
        "netbank", "mitid", "mobilpay", "lunar", "revolut", "telenor", "telia", "3dk", "borger", "politi", "oandora", "virk", "lego", "vestas","Ørsted",  "sundhed", "dsb", "dot", 
        "rejsekort", "sas", "flixbus", "postnord", "jysk", "føtex", "bilka", "matas", ]

# from:
# - https://dl.acm.org/doi/10.1145/1314389.1314391
# - https://dl.acm.org/doi/abs/10.1145/3465481.3470111
sus_keywords=["secure", "account", "webscr", "login", "ebayisapi", "signin", "banking", "confirm", "support",
    "update", "verify", "center", "paypal", "sharepoint", "windows", "onedrive", "cartetitolarI",
    "recovery", "verification", "runescape", "sagawa", "office", "ebay", "viabcp", "mail", "services",
    "info", "mobile", "auth", "google", "appleid", "facebook", "allegro", "service", "security",
    "secureserver", "promo", "apple", "amazon", "1drv", "itau", "online", "docs", "help", "storage",
    "free", "jppost", "icloud", "live", "bankofamerica"
]

vowels="aeiou"

def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

def brand_inclusion(domain):
    domain_lower= domain.lower()
    return any(brand in domain_lower for brand in brands)


def detect_punycode(domain):
    return domain.startswith("xn--")


def detect_homoglyph(domain):
    domain = domain.lower()
    homoglyphs_found = []
    homoglyph_dict = {}

    #load file from source: https://github.com/codebox/homoglyph/tree/master
    with open("./chars.txt", "r") as file:
        lines= file.readlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        homoglyphs = line.split()
        for char in homoglyphs:
            if char not in homoglyph_dict:
                homoglyph_dict[char] = set()
            for other_char in homoglyphs:
                if char != other_char:
                    homoglyph_dict[char].add(other_char)

    for char in domain:
        if char in homoglyph_dict:
            for homoglyph in homoglyph_dict[char]:
                if homoglyph in domain and homoglyph != char:
                    homoglyphs_found.append((char, homoglyph))
    
    return homoglyphs_found

def get_dns_ttl(domain):
    try:
        answers= dns.resolver.resolve(domain, 'A')
        return answers.rrset.ttl
    except:
        None

def resolve_ip(domain):
    try:
        answers= dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except:
        return []
    
# hosting provider
def get_asn_info(ip_list):
    if not ip_list:
        return None
    ip = ip_list[0]  # Fix
    
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data=r.json()
        organization= data.get("org")
        return organization
    except:
        pass
        return None

def calculate_domain_age(creation_date):
    """Calculate the age of the domain in years."""
    if creation_date:
        # Parse the creation date
        creation_date = datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%S.%fZ')  # Example format, adjust as necessary
        today = datetime.today()
        age = today - creation_date
        return age.days
    return None

def parse_domain_features(domain)-> dict:
    parts = tldextract.extract(domain)
    domain_name= parts.domain

    #subdomain features
    subdomain_count= len(parts.subdomain.split(".")) if parts.subdomain else 0  # Exclude the main domain and TLD
    subdomains = parts.subdomain.split(".") if parts.subdomain else []
    subdomain_length= [len(s) for s in subdomains]
    
    #suspicious keywords
    suspicious_hits = [k for k in sus_keywords if k in domain]
    sus_count= len(suspicious_hits)

    #fraction of domain that are vowels
    vowels_count = sum(1 for c in domain if c in vowels)
    fraction_vowels = vowels_count / len(domain_name) if domain_name else 0

    # fraction of domain that are digits
    digits_count = sum(1 for c in domain_name if c.isdigit())
    fraction_digits = digits_count / len(domain_name) if domain_name else 0


    #DNS
    ttl = get_dns_ttl(domain)
    ip = resolve_ip(domain)
    asn_info = get_asn_info(ip) if ip else None

    result={
        "length": len(domain),
        "shannon_entropy": shannon_entropy(domain),
        "tokens": re.split(r'[-.]', domain),
        "token_count": len(re.split(r'[-.]', domain)),
        "hyphen_count": domain.count('-'),
        "subdomain_count": subdomain_count,
        "mean_subdomain_length": sum(subdomain_length)/len(subdomain_length) if subdomain_length else 0,
        "subdomain_only_digits": any(subdomain.isdigit() for subdomain in subdomains),
        "single_char_subdomains": any(len(subdomain) == 1 for subdomain in subdomains),
        "unique_char_count_domain": len(set(domain)),
        "special_chars": len(re.findall(r'[^a-zA-Z0-9.-]', domain)),
        "fraction_vowels": fraction_vowels,
        "fraction_digits": fraction_digits,
        "suspicious_keywords_count": sus_count,
        "suspicious_keywords": suspicious_hits,
        "brand_inclusion": brand_inclusion(domain),
        "idn_punycode": detect_punycode(domain),
        "idn_hymoglyph": detect_homoglyph(domain),
        "dns_ttl": ttl,
        "ip": ip,
        "hosting_asn": asn_info,
    }

    

    return result


def parse_whois_feautures(domain, netlas_connection):
    query = f"domain:{domain}"

    attempt =0
    total_wait_time=0
    max_wait_time=180

    while attempt < 2:
        try:

            print("Querying WHOIS for domain:", domain)
            raw_results = netlas_connection.search(query, datatype="whois-domain")
            
            if raw_results and raw_results["items"]:
                whois_item= raw_results["items"][0]["data"]
            
            # registrar information
                registrar_name=None
                if "registrar" in whois_item:
                    registrar= whois_item["registrar"]
                    registrar_name= registrar.get("name", None) 

            # registrant information
                registrant_name=None
                registrant_country=None
                if "registrant" in whois_item:
                    registrant= whois_item["registrant"]
                    registrant_name= registrant.get("name", None)
                    registrant_country=registrant.get("country", None)

                # creation date
                created_date= whois_item.get("created_date", None)
                domain_age= calculate_domain_age(created_date) 
                
                return{
                    "creation_date": created_date,
                    "expiration_date": whois_item.get("expiration_date", None),
                    "domain_age": domain_age,
                    "registrant_country": registrant_country,
                    "registrant_name": registrant_name,
                    "registrar_name": registrar_name,
                    "status": whois_item.get("status", None),
                }
            else:
                print(f"No WHOIS data found for {domain}")
                return {}

    
    
        except netlas.ThrottlingError as e:
            print(f"Error fetching WHOIS for {domain}: {e}")

            time.sleep(e.retry_after)
            total_wait_time += e.retry_after
            attempt += 1

            if total_wait_time >= max_wait_time:
                break

    
    return {}
        


def process_domain(df, output_path, delay=1):
    api_key=netlas.helpers.get_api_key()
    netlas_connection = netlas.Netlas(api_key)
    
    results=[]
    for index, row in df.iterrows():
        domain= row['Domæne']
        whois_data= parse_whois_feautures(domain, netlas_connection)
        domain_data=parse_domain_features(domain)
        combined_data={**row.to_dict(),**domain_data, **whois_data}
        results.append(combined_data)
        time.sleep(delay)

    #write to csv
    if results:
        fieldnames= list(results[0].keys())
    else:
        fieldnames= []

    with open(output_path, "w", newline="") as f:
        writer=csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)



