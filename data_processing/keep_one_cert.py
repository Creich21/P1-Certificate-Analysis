import os
import shutil
import pandas as pd
from pathlib import Path
import json
import datetime
from dateutil import parser

def parse_timestamp(ts_str):
    """
    Convert a timestamp string from your JSON to a datetime object
    """
    if ts_str is None:
        return None
    try:
        # handle Z suffix
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception as e:
        try:
            return parser.isoparse(ts_str)
        except Exception:
            return None

# for the phishing domain, only keep one certificate which is closest before the reported date
def keep_one_cert():
    abuse_csv=input("Enter the path to the phishing CSV file: ").strip()
    json_folder = input("Enter the path to the folder with JSON files: ").strip()
    output_folder = input("Enter the output folder path: ").strip()

    df=pd.read_csv(abuse_csv)
    df["added"]=pd.to_datetime(df["added"], utc=True)

    abuse_dates=dict(zip(df["domain_name"], df["added"]))

    # --- PREPARE OUTPUT FOLDER ---
    dst = Path(output_folder)
    dst.mkdir(exist_ok=True)

    # --- PROCESS JSON FILES ---
    src = Path(json_folder)
    json_files = list(src.glob("*.json"))

    for file in json_files:
        domain=file.stem
        print("Processing:", file.name)

        if domain not in abuse_dates:
            print("  ❌ Domain not in abusemanager → copying unchanged")
            shutil.copy2(file, dst / file.name)
            continue
    

        added_date = abuse_dates.get(domain)
        print("  ✔ Abuse date:", added_date)

        try:
            data = json.loads(file.read_text())
        except Exception as e:
            print(f"Error reading {file.name}: {e}")
            continue
        
        if not isinstance(data, list) or len(data) == 0:
            shutil.copy2(file, dst / file.name)
            continue

        print("  ✔ Certificates found:", len(data))

        before = []
        after=[]
        
        for entry in data:
            try:
                ts_str = entry["data"]["timestamp"]
                print(f"    - Found timestamp: {ts_str} for domain {domain}")
                #ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = parse_timestamp(ts_str)
                print(f"    - Parsed timestamp: {ts} for domain {domain}")
            except Exception as e:
                print(f"    ❌ Error parsing timestamp for domain {domain}: {e}")
                continue
            if ts <= added_date:
                before.append((ts,entry))
            else:
                after.append((ts,entry))

        print("  ✔ Certs before added date:", len(before))

        #Case A: choose nearest certificate before added time
        if before:
            before.sort(key=lambda x: x[0], reverse=True)
            best_entry = before[0][1]

        elif after:
            after.sort(key=lambda x: x[0])
            best_entry = after[0][1]

        else:
            shutil.copy2(file, dst / file.name)
            continue

        # -- WRITE OUTPUT FILE ---
        out_path= dst / file.name
        with out_path.open("w", encoding="utf-8") as f:
            json.dump([best_entry], f, indent=2, ensure_ascii=False)

        print("Processed:", file.name)


# for the popular and unpopular domains, keep only the most recent certificate
def most_recent_cert():
    #abuse_csv=input("Enter the path to the abuse CSV file: ").strip()
    json_folder = input("Enter the path to the folder with JSON files: ").strip()
    output_folder = input("Enter the output folder path: ").strip()

    # --- PREPARE OUTPUT FOLDER ---
    dst = Path(output_folder)
    dst.mkdir(exist_ok=True)

    # --- PROCESS JSON FILES ---
    src = Path(json_folder)
    json_files = list(src.glob("*.json"))

    for file in json_files:
        domain=file.stem
        print("Processing:", file.name)

        try:
            data = json.loads(file.read_text())
        except Exception as e:
            print(f"Error reading {file.name}: {e}")
            continue
        
        if not isinstance(data, list) or len(data) == 0:
            shutil.copy2(file, dst / file.name)
            continue
        most_recent = None
        most_recent_ts = None
        
        for entry in data:
            try:
                ts_str = entry["data"]["timestamp"]
                print(f"Found timestamp: {ts_str} for domain {domain}")
                #ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = parse_timestamp(ts_str)
                print(f"Parsed timestamp: {ts} for domain {domain}")
            except Exception as e:
                print(f"Error parsing timestamp for domain {domain}: {e}")
                continue
            
            if ts is None:
                continue

            if most_recent is None or ts > most_recent_ts:
                most_recent = entry
                most_recent_ts = ts

        if most_recent is None:
            shutil.copy2(file, dst / file.name)
            continue

        # -- WRITE OUTPUT FILE ---
        out_path= dst / file.name
        with out_path.open("w", encoding="utf-8") as f:
            json.dump([most_recent], f, indent=2, ensure_ascii=False)

        print("Processed:", file.name)


def extract_features(cert):
       
    flattened= {}

    issuer = cert.get("issuer", {})
    flattened["issuer_dn"] = cert.get("issuer_dn")
    flattened["issuer_country"] = ",".join(issuer.get("country", [])) if issuer.get("country") else None
    flattened["issuer_organization"] = ",".join(issuer.get("organization", [])) if issuer.get("organization") else None
    flattened["issuer_common_name"] = ",".join(issuer.get("common_name", [])) if issuer.get("common_name") else None

    # subject
    subject = cert.get("subject", {})
    flattened["subject_dn"] = cert.get("subject_dn")
    flattened["subject_country"] = ",".join(subject.get("country", [])) if subject.get("country") else None
    flattened["subject_organization"] = ",".join(subject.get("organization", [])) if subject.get("organization") else None
    flattened["subject_common_name"] = ",".join(subject.get("common_name", [])) if subject.get("common_name") else None

    # basic certificate info
    flattened["serial_number"] = cert.get("serial_number")
    flattened["version"] = cert.get("version")
    flattened["validation_level"] = cert.get("validation_level")
    flattened["redacted"] = cert.get("redacted")
    flattened["src"] = cert.get("src")
    
    # validity
    validity = cert.get("validity", {})
    flattened["validity_length"] = validity.get("length")
    flattened["validity_start"] = validity.get("start")
    flattened["validity_end"] = validity.get("end")

    # signature
    signature = cert.get("signature", {})
    flattened["signature_valid"] = signature.get("valid")
    flattened["signature_value"] = signature.get("value")
    flattened["self_signed"] = signature.get("self_signed")
    sig_alg = signature.get("signature_algorithm", {})
    flattened["signature_algorithm_name"] = sig_alg.get("name")
    flattened["signature_algorithm_oid"] = sig_alg.get("oid")

    # fingerprints
    fingerprints = cert.get("fingerprints", {})
    flattened["fingerprint_md5"] = fingerprints.get("md5")
    flattened["fingerprint_sha1"] = fingerprints.get("sha1")
    flattened["fingerprint_sha256"] = fingerprints.get("sha256")
    flattened["fingerprint_tbs"] = fingerprints.get("tbs")
    flattened["fingerprint_tbs_noct"] = fingerprints.get("tbs_noct")
    flattened["fingerprint_spki_subject"] = fingerprints.get("spki_subject")

    # extensions
    extensions = cert.get("extensions", {})
    flattened["crl_distribution_points"] = extensions.get("crl_distribution_points")
    flattened["subject_key_id"] = extensions.get("subject_key_id")
    
    # certificate policies
    policies = cert.get("extensions", {}).get("certificate_policies", []) or []
    flattened["certificate_policy_ids"] = ",".join([p.get("id","") for p in policies]) if policies else None

    # key usage
    key_usage = cert.get("extensions", {}).get("key_usage", {}) or {}
    flattened["key_digital_signature"] = key_usage.get("digital_signature")
    flattened["key_certificate_sign"] = key_usage.get("certificate_sign")
    flattened["key_crl_sign"] = key_usage.get("crl_sign")
    flattened["key_encipherment"] = key_usage.get("key_encipherment")
    flattened["key_usage_value"] = key_usage.get("value")


    # extended key usage
    ext_key_usage = cert.get("extensions", {}).get("extended_key_usage", {}) or {}
    flattened["key_client_auth"] = ext_key_usage.get("client_auth")
    flattened["key_server_auth"] = ext_key_usage.get("server_auth")

    # basic constraints
    basic_constraints = cert.get("extensions", {}).get("basic_constraints", {}) or {}
    flattened["is_ca"] = basic_constraints.get("is_ca")
    flattened["max_path_length"] = basic_constraints.get("max_path_len")

    # authority info access
    aia = extensions.get("authority_info_access") or {}
    flattened["authority_info_access_issuer_urls"] = aia.get("issuer_urls")
    

    # SAN
    san = extensions.get("subject_alt_name") or {}
    flattened["san_list"] = san.get("dns_names")

    # signed certificate timestamps
    scts = extensions.get("signed_certificate_timestamps") or []
    flattened["signed_certificate_timestamps"] = scts
    flattened["sct_count"] = len(scts)

    # features
    features = cert.get("features", {})
    for k,v in features.items():
        flattened[f"{k}"] = v

    return flattened


# convert the json folder resulting from netlas to a csv file
def convert_to_csv():
    csv_path = input("Enter the path to the csv dataset: ").strip() # for general information (features will be added to this)
    json_folder_path = input("Enter the path to the folder with JSON files: ").strip()
    output_csv = input("Enter the output CSV file path: ").strip()

    df= pd.read_csv(csv_path)

    # process json folder
    json_folder = Path(json_folder_path)
    cert_rows=[]

    for file in json_folder.glob("*.json"):
        domain = file.stem
        try:
            data = json.loads(file.read_text())
        except Exception as e:  
            print(f"Error reading {file.name}: {e}")
            continue

        if not data or not isinstance(data, list):
            cert_rows.append({"domain":domain})
            continue

        entry = data[0]
        cert=entry["data"].get("certificate")
        if isinstance(cert, dict):
            flattened= extract_features(cert)
            flattened["domain"]=domain
            cert_rows.append( flattened)
        else:
            cert_rows.append({"domain":domain})

    cert_df = pd.DataFrame(cert_rows)


    cert_df.rename(columns={"domain":"Domæne"}, inplace=True)

    merged_df= df.merge(cert_df, on="Domæne", how="left")
    
    #save to csv
    merged_df.to_csv(output_csv, index=False)




if __name__ == "__main__":
    #
    # keep only one cert before abuse date from pishing domain
    #keep_one_cert() 

    # convert filtered phishing cert json to csv
    convert_to_csv()

    # keep most recent cert from phishing domain
    #most_recent_cert()
