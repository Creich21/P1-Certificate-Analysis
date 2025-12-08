#Hypothesis 3. It is expected to see a correlation between missing information fields and a high likelihood of phishing
#Also checks if certificate is self-signed or not
# in P1-Certificate-Analysis run python3 -m hypothesis.hypothesis3

import csv
import datetime
import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Literal


import pandas as pd
from colorama import Fore, Style


from cert_analyzer.analysis.basic_analysis import (
    _parse_iso_z,
    days_until_expiry,
    is_expired,
)
from cert_analyzer.models.certificates import Certificate
from cert_analyzer.models.features import CertificateFeatures
from cert_analyzer.models.results import CertificateItem, Highlight

from hypothesis.csv_plots.csv_plots import (
    plot_empty_certificates,
    plot_missing_rate_per_field,
    plot_most_common_missing_fields,
    plot_summary_statistics,
)

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

field_missing_count: Counter[str] = Counter()
domain_missing_count: defaultdict[str, list[int]] = defaultdict(list)
missing_count_dist: Counter[int] = Counter()
validation_level_counts: Counter[str] = Counter()
DomainMissingCount = defaultdict[str, list[int]]




def get_filename_from_path(file_path: Path) -> str:
    """Extract just the filename from a full path"""
    return file_path.name

def check_if_json_is_empty(f, json_data, logger, message:str="") -> bool:
    if json_data is None or json_data == []:
        logger.error(f"No certificate in {get_filename_from_path(f)}. {message}")
        return True
    return False




def custom_logger() -> logging.Logger:
    """Create a logger to log alerts to console and file."""
    logger = logging.getLogger("certificate_alerts")


    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")


    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)


    log_path = Path("popular_certificate_alerts.log")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger




def calculate_certificate_lifespan_days(certificate: Certificate) -> int:
    """Calculate the total lifespan of a certificate in days."""
    start_str = certificate.validity.get("start")
    end_str = certificate.validity.get("end")

    if not start_str or not end_str:
        return 0

    start_date = _parse_iso_z(start_str)
    end_date = _parse_iso_z(end_str)

    if not start_date or not end_date:
        return 0

    lifespan = (end_date - start_date).days
    return lifespan

def get_certs_dir(category: Literal["blocked", "popular", "unpopular"]) -> Path:
    """
    Returns the file path to the directory containing certificates for a 
    specified category (blocked, popular, or unpopular).

    """
    
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    data_dir = project_root / "data"
    
    # Determine the specific path based on the category
    if category == "blocked":
        certs_dir = data_dir / "blocked_certs" / "most_recents"
    elif category == "popular":
        certs_dir = data_dir / "popular_certs" / "most_recents"
    elif category == "unpopular":
        certs_dir = data_dir / "unpopular_certs"
    else:
        raise ValueError(
            f"Invalid category: '{category}'. Must be 'blocked', 'popular', or 'unpopular'."
        )

    if not certs_dir.exists():
         print(f"Warning: Certificate directory not found at {certs_dir}")

    return certs_dir




def get_blocked_certs_dir() -> Path:
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    data_dir = project_root / "data"
    blocked_dir = data_dir / "blocked_certs/most_recents"
    return blocked_dir

def validate_directory(directory: Path) -> bool:
    """Check if directory exists and is valid"""
    if not directory.exists():
        print(f"Directory {directory} does not exist")
        return False
    return True

def parse_certificates(json_data: List[Dict[str, Any]]) -> List[CertificateItem]:
    """
    Parse certificates from a single JSON data list.
    
    Args:
        json_data: List of certificate dictionaries
        
    Returns:
        List of parsed CertificateItem objects
    """
    certificates = []
    
    for item in json_data:
        try:
            h = item.get("highlight", {})
            
            highlight = Highlight(
                certificate_subject_dn=h.get("certificate_subject_dn"),
            )


            cert_dict = item["data"]["certificate"]

            subject_dn = cert_dict.get("subject_dn", "")
            issuer_dn = cert_dict.get("issuer_dn", "")
            serial_number = cert_dict.get("serial_number", "")
            version = cert_dict.get("version", "")
            validation_level = cert_dict.get("validation_level", "")
            src = cert_dict.get("src", "")
            redacted = cert_dict.get("redacted", False)
            subject = cert_dict.get("subject", "")
            issuer = cert_dict.get("issuer", "")

            fingerprints = cert_dict.get("fingerprints") or {
                "tbs": cert_dict.get("tbs_fingerprint"),
                "tbs_noctl": cert_dict.get("tbs_noctl_fingerprint"),
                "sha1": cert_dict.get("fingerprint_sha1"),
                "spki_subject": cert_dict.get("spki_subject_fingerprint"),
                "md5": cert_dict.get("fingerprint_md5"),
                "sha256": cert_dict.get("fingerprint_sha256"),


            }
            signature = cert_dict.get("signature", "")
            signature_algorithm = cert_dict.get("signature_algorithm", "")
            validity = cert_dict.get("validity", "")
            extensions = cert_dict.get("extensions", "")
            names = cert_dict.get("names")
            chain = cert_dict.get("chain", "")

            certificate = Certificate(
                issuer_dn=issuer_dn,
                subject_dn=subject_dn,
                serial_number=serial_number,
                version=version,
                validation_level=validation_level,
                src=src,
                redacted=redacted,
                subject=subject,
                issuer=issuer,
                fingerprints=fingerprints,
                signature=signature,
                signature_algorithm=signature_algorithm,
                validity=validity,
                extensions=extensions,
                names=names,
                chain=chain,)
            
            try:
                san = certificate.extensions.get("subject_alt_name", {}).get("dns_names", [])
            except (KeyError, TypeError):
                san = []
            if san:
                num_san_dns_names = len(san)
                san_has_wildcard_dns = any(n.startswith("*.") for n in san)
                san_has_exact_subdomain_dns = any("." in n and not n.startswith("*.") for n in san)
            else:
                num_san_dns_names = 0
                san_has_wildcard_dns = False
                san_has_exact_subdomain_dns = False


            # Time-related features
            days_left = days_until_expiry(certificate)
            valid_time_so_far_days = (datetime.datetime.now(datetime.timezone.utc) - _parse_iso_z(certificate.validity.get("start"))).days
            has_expired = is_expired(certificate)


            # PKI-related features
            bc = certificate.extensions.get("basic_constraints", {})
            key_usage = certificate.extensions.get("key_usage", {})
            is_trusted_certificate = bc.get("is_ca") if bc else None
            key_cert_sign = key_usage.get("certificate_sign") if key_usage else None


            certificate.features = CertificateFeatures(
                days_until_expiry=days_left,
                valid_time_so_far_days=valid_time_so_far_days,
                has_expired=has_expired,
                serial_number_length=len(certificate.serial_number) if certificate.serial_number else 0,
                num_san_dns_names=num_san_dns_names if san else 0,
                san_has_wildcard_dns=san_has_wildcard_dns if san else False,
                san_has_exact_subdomain_dns=san_has_exact_subdomain_dns if san else False,
                is_trusted_certificate=is_trusted_certificate,
                key_cert_sign=key_cert_sign,
            )

        except Exception as e:
            print(Fore.RED + f"Error parsing highlight: {e}" + Style.RESET_ALL)
            continue


        certificates.append(certificate)
    print(f"Total certificates parsed: {len(certificates)}")
    return certificates

def check_for_missing_fields(certificate: Certificate, logger) -> List[str]:
    """Check for missing fields in a certificate and set alerts accordingly."""

    missing_fields = []
    if not certificate.subject_dn:
        missing_fields.append("subject_dn")
    if not certificate.issuer_dn:
        missing_fields.append("issuer_dn")
    if not certificate.serial_number:
        missing_fields.append("serial_number")
    if not certificate.version:
        missing_fields.append("version")

    
    # Check validity fields
    if certificate.validity is not None:

        if not certificate.validity.get("start"):
            missing_fields.append("validity.start")
        if not certificate.validity.get("end"):
            missing_fields.append("validity.end")
        
    else:
        missing_fields.append("validity")


    #Check validation levels
    if not certificate.validation_level:
        missing_fields.append("validation_level")

    #Check src
    if not certificate.src:
        missing_fields.append("src")

    #Check redacted
    if certificate.redacted is None:
        missing_fields.append("redacted")

    #Check fingerprints
    if certificate.fingerprints is not None:
        fingerprints = certificate.fingerprints
        if not fingerprints.get("sha256"):
            missing_fields.append("fingerprints.sha256")
        if not fingerprints.get("sha1"):
            missing_fields.append("fingerprints.sha1")
        if not fingerprints.get("md5"):
            missing_fields.append("fingerprints.md5")
    else:
        missing_fields.append("fingerprints") 


    #Check subject
    if certificate.subject is not None:
        subject = certificate.subject


        if not subject.get("common_name"):
            missing_fields.append("subject_common_name")
        if not subject.get("organization"):
            missing_fields.append("subject_organization")
        if not subject.get("country"):
            missing_fields.append("subject_country")

    else:
        missing_fields.append("subject")

    #Check issuer
    if certificate.issuer is not None:
        issuer = certificate.issuer


        if not issuer.get("common_name"):
            missing_fields.append("issuer_common_name")
        if not issuer.get("organization"):
            missing_fields.append("issuer_organization")
        if not issuer.get("country"):
            missing_fields.append("issuer_country")

    else:
        missing_fields.append("issuer")

    #Check signatures
    if certificate.signature is not None:
        signature = certificate.signature
        if not signature.get("value"):
            missing_fields.append("signature_value")
    else:
        missing_fields.append("signature")



    #Check signature_algorithm
    if certificate.signature_algorithm is not None:
        signature_algorithm = certificate.signature_algorithm
        if not signature_algorithm.get("name"):
            missing_fields.append("signature_algorithm_name")

    else:
        missing_fields.append("signature_algorithm")


    
    #Check names
    if certificate.names is None or certificate.names == []:
        missing_fields.append("names")

    #Check chains
    if certificate.chain is None or certificate.chain == []:
        missing_fields.append("chain")


    #Check extensions
    if certificate.extensions is not None:
        authority_info_access = certificate.extensions.get("authority_info_access")
        authority_key_id = certificate.extensions.get("authority_key_id")
        basic_constraints = certificate.extensions.get("basic_constraints")
        certificate_policies = certificate.extensions.get("certificate_policies")
        crl_distribution_points = certificate.extensions.get("crl_distribution_points")
        extended_key_usage = certificate.extensions.get("extended_key_usage")
        key_usage = certificate.extensions.get("key_usage")
        signed_certificate_timestamps = certificate.extensions.get("signed_certificate_timestamps")
        subject_alt_name = certificate.extensions.get("subject_alt_name")
        subject_key_id = certificate.extensions.get("subject_key_id")

        if authority_info_access is not None:
            if authority_info_access.get("issuer_urls") is None:
                missing_fields.append("extensions.authority_info_access.issuer_urls")
            if authority_info_access.get("ocsp_urls") is None:
                missing_fields.append("extensions.authority_info_access.ocsp_urls")
        else:
            missing_fields.append("extensions.authority_info_access")



        if authority_key_id is None:
            missing_fields.append("extensions.authority_key_id")


        if basic_constraints is None:
            missing_fields.append("extensions.basic_constraints")


        if certificate_policies is None:
            missing_fields.append("extensions.certificate_policies")


        if crl_distribution_points is None:
            missing_fields.append("extensions.crl_distribution_points")
        if extended_key_usage is None:
            missing_fields.append("extensions.extended_key_usage")
        if key_usage is None:
            missing_fields.append("extensions.key_usage")
        if signed_certificate_timestamps is None:
            missing_fields.append("extensions.signed_certificate_timestamps")
        if subject_alt_name is None:
            missing_fields.append("extensions.subject_alt_name")
        if subject_key_id is None:
            missing_fields.append("extensions.subject_key_id")

    if missing_fields:
        prefix = f"Certificate {certificate.subject_dn} is missing fields: "
        fields_str = ", ".join(missing_fields)

        logger.warning(Fore.RED + f"{prefix}{fields_str}" + Style.RESET_ALL)


    return missing_fields






def check_if_certificate_is_self_signed(certificate: Certificate, logger) -> None:
    sig = certificate.signature or {}
    is_self_signed = sig.get("self_signed")


    if is_self_signed:
        logger.warning(f"Certificate {certificate.subject_dn} is self-signed.")



def validation_level_counter(level: str) -> None:
    """Count occurrences of different validation levels (DV, EV, OV)."""
    level = level.lower() if level else "none"
    validation_level_counts[level] += 1
    return




# Statistical Analysis Functions



def compute_summary_stats(df: pd.DataFrame, logger) -> pd.DataFrame:
    """
    Compute summary statistics (mean, median, std, min, max) per category.
    """
    stats_missing = df.groupby("label")["missing_count"].agg(["mean", "median", "std", "min", "max"])
    logger.info(Fore.GREEN + "Summary statistics per category:" + Style.RESET_ALL)
    logger.info(f"\n{stats_missing}")

    plot_summary_statistics(stats_missing, output_folder="hypothesis/csv_plots")
    return stats_missing


def most_common_missing_fields_overall(df: pd.DataFrame, top_n: int = 20) -> Counter:
    """
    Count most commonly missing fields across all categories.
    """
    all_fields = Counter()
    for row in df["missing_fields"]:
        all_fields.update(row)

    print("Most commonly missing fields (overall):")
    for field, count in all_fields.most_common(top_n):
        print(f"{field}: {count}")

    plot_most_common_missing_fields(all_fields, output_folder="hypothesis/csv_plots", filename="most_common_missing_fields.png")
    return all_fields


def most_missing_fields_per_category(df: pd.DataFrame, top_n: int = 10) -> Dict[str, Counter]:
    """
    Count most missing fields per category.
    """
    missing_by_cat = defaultdict(Counter)
    for _, row in df.iterrows():
        missing_by_cat[row["label"]].update(row["missing_fields"])

    print("\nMost missing fields per category:\n")
    for cat, counter in missing_by_cat.items():
        print(f"\nCategory: {cat}")
        for field, count in counter.most_common(top_n):
            print(f"{field}: {count}")
    return missing_by_cat


def missing_rate_per_field(df: pd.DataFrame, missing_by_cat: Dict[str, Counter], top_n: int = 10) -> Dict[str, Dict[str, float]]:
    """
    Compute missing rate (percentage) per field for each category.
    """
    missing_rate = {}
    for cat, counter in missing_by_cat.items():
        total = len(df[df["label"] == cat])
        missing_rate[cat] = {field: (count / total) * 100 for field, count in counter.items()}

    print("\nMissing rate (%) per field per category:\n")
    for cat in missing_rate:
        print(f"\nCategory: {cat}")
        for field, pct in sorted(missing_rate[cat].items(), key=lambda x: -x[1])[:top_n]:
            print(f"{field}: {pct:.2f}%")

    plot_missing_rate_per_field(missing_rate, output_folder="hypothesis/csv_plots", filename="missing_rate_per_field.png")
    return missing_rate

def empty_certificate_analysis(df: pd.DataFrame, logger) -> None:
    # Count of empty certificates per category
    empty_counts = df.groupby("label")["no_certificate"].sum()
    
    # Total certificates per category
    total_counts = df.groupby("label").size()
    
    # Percentage of empty certificates per category
    empty_percentage = (empty_counts / total_counts) * 100

    # Combine results into a single DataFrame for nicer logging
    summary_df = pd.DataFrame({
        "total_certificates": total_counts,
        "empty_certificates": empty_counts,
        "empty_percentage": empty_percentage
    })

    logger.info(Fore.GREEN + "Empty certificate analysis per category:" + Style.RESET_ALL)
    logger.info(Fore.GREEN + f"\n{summary_df}" + Style.RESET_ALL)


    plot_empty_certificates(summary_df, output_folder="hypothesis/csv_plots", filename="empty_certificates.png")

def statistical_analysis(df: pd.DataFrame, logger) -> None:

    
    empty_certificate_analysis(df, logger)
    compute_summary_stats(df, logger)
    all_fields = most_common_missing_fields_overall(df)
    missing_by_cat = most_missing_fields_per_category(df)
    missing_rate = missing_rate_per_field(df, missing_by_cat)



def read_netlas_certs(logger):

    categories = {
        "Blocked": get_certs_dir("blocked"),
        "Popular": get_certs_dir("popular"),
        "Unpopular": get_certs_dir("unpopular"),
    }

    
    results = []
    
    total_certificates = 0
    domains_with_certs = 0
    json_data = []
    non_certificate_domain_counter = 0


    for label, directory in categories.items():
        if not validate_directory(directory):
            logger.error(f"Invalid directory for category '{label}': {directory}")
            continue


        json_files = list(directory.glob("*.json"))
        logger.info(f"{label}: Found {len(json_files)} JSON files in {directory}")

        for file_path in json_files:
            file_name = get_filename_from_path(file_path)
            logger.info(f"Processing file: {file_name} in category: {label}")

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

            except json.JSONDecodeError as e:
                logger.error(f"Error reading {file_path}: {e}")
                continue
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                continue

            # Check how many of domains have no certificates
            if check_if_json_is_empty(file_path, data, logger):
                non_certificate_domain_counter += 1
                
                results.append({
                    "label": label,
                    "missing_count": None,              
                    "missing_fields": [],               
                    "domain": file_path.stem,
                    "no_certificate": True
                })
                
                continue
            domains_with_certs += 1

            #Parse certificates for each domain
            certificates = parse_certificates(data)
            for certificate in certificates:
                total_certificates += 1
                missing_fields = check_for_missing_fields(certificate, logger)
                
                results.append({
                    "label": label,
                    "missing_count": len(missing_fields),
                    "missing_fields": missing_fields,
                    "domain": certificate.subject_dn,
                    "no_certificate": False
                })


    logger.info(Fore.BLUE + f"Number of non-certificate domains: {non_certificate_domain_counter}" + Style.RESET_ALL)
    logger.info(Fore.BLUE + f"Total domains with certificates: {domains_with_certs}" + Style.RESET_ALL)
    logger.info(Fore.BLUE + f"Total domains processed: {non_certificate_domain_counter + domains_with_certs}" + Style.RESET_ALL)
    logger.info(Fore.BLUE + f"Total certificates processed: {total_certificates}" + Style.RESET_ALL)

    df = pd.DataFrame(results)

    statistical_analysis(df,logger)

    return results


def main():
    logger = custom_logger()
    logger.info("Starting analysis of blocked Netlas certificates...")
    read_netlas_certs(logger)
    logger.info("Completed analysis of blocked Netlas certificates.")

if __name__ == "__main__":
    main()



