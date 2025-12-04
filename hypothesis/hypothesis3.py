#Hypothesis 3. It is expected to see a correlation between missing information fields and a high likelihood of phishing
#Also checks if certificate is self-signed or not
# in P1-Certificate-Analysis run python3 -m hypothesis.hypothesis3
import csv
import datetime
import json
from pathlib import Path
import sys
from colorama import Fore, Style
from cert_analyzer.analysis.basic_analysis import _parse_iso_z, days_until_expiry, is_expired
import logging



project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from typing import Any, Dict, List
from cert_analyzer.models.results import CertificateItem
from cert_analyzer.models.features import CertificateFeatures

from cert_analyzer.models.results import Highlight
from cert_analyzer.models.certificates import Certificate

from collections import Counter, defaultdict

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



def get_blocked_certs_dir() -> Path:
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    data_dir = project_root / "data"
    blocked_dir = data_dir / "popular_domain_certs"
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

        logger.warning(f"{prefix}{fields_str}")


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




def write_field_stats_csv(field_missing_count: Counter, filename: str = "hypothesis/csv_plots/field_stats.csv") -> None:
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "missing_count"])
        for field, cnt in field_missing_count.items():
            writer.writerow([field, cnt])

def write_domain_stats_csv(domain_missing_count: defaultdict[str, list[int]], filename: str = "hypothesis/csv_plots/domain_stats.csv") -> None:
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["subject_dn", "avg_missing_fields"])
        for domain, counts in domain_missing_count.items():
            avg = sum(counts) / len(counts)
            writer.writerow([domain, avg])

def write_missing_count_dist_csv(missing_count_dist: Counter, filename="hypothesis/csv_plots/missing_count_dist.csv") -> None:
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["num_missing_fields", "num_certificates"])
        for k, cnt in sorted(missing_count_dist.items()):
            writer.writerow([k, cnt])


def write_domain_detail_csv(domain_missing_count: DomainMissingCount,
                            filename: str = "hypothesis/csv_plots/domain_detail.csv") -> None:
    """
    Write per-domain stats to CSV with columns:
      subject_dn, avg_missing_fields, max_missing_fields, num_certs
    """
    stats = compute_domain_stats(domain_missing_count)

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["subject_dn", "avg_missing_fields", "max_missing_fields", "num_certs"])
        for domain, vals in stats.items():
            writer.writerow([domain, vals["avg"], vals["max"], vals["num_certs"]])

def write_overview_csv(
    non_certificate_domain_counter: int,
    domains_with_certs: int,
    total_certificates: int,
    filename: str = "hypothesis/csv_plots/overview_stats.csv",
) -> None:
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["Non Certificate Domains", non_certificate_domain_counter])
        writer.writerow(["Domains With Certificates", domains_with_certs])

def write_validation_level_csv(validation_level_counts: Counter, filename: str = "hypothesis/csv_plots/validation_level_stats.csv") -> None:
    """Write validation level counts to CSV"""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["validation_level", "count"])
        for level, cnt in validation_level_counts.items():
            writer.writerow([level, cnt])





def compute_domain_stats(domain_missing_count: DomainMissingCount) -> Dict[str, Dict[str, float]]:
    """
    For each domain, compute:
      - avg_missing_fields
      - max_missing_fields
      - num_certs
    Returns a dict: {domain: {"avg": float, "max": int, "num_certs": int}}
    """
    stats: Dict[str, Dict[str, float]] = {}

    for domain, counts in domain_missing_count.items():
        if not counts:
            continue
        avg_val = sum(counts) / len(counts)
        max_val = max(counts)
        stats[domain] = {
            "avg": avg_val,
            "max": max_val,
            "num_certs": len(counts),
        }

    return stats



def read_netlas_certs_blocked(logger):
    blocked_dir = get_blocked_certs_dir()
    if not validate_directory(blocked_dir):
        return []
    
    total_certificates = 0
    domains_with_certs = 0
    json_data = []
    non_certificate_domain_counter = 0

    for file_path in blocked_dir.glob("*.json"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                file_name = get_filename_from_path(file_path)
                logger.info(f"Processing file: {file_name}")

                # Check how many of domains have no certificates
                if check_if_json_is_empty(file_path,data,logger):
                    non_certificate_domain_counter += 1
                    continue
                
                domains_with_certs += 1
                
                #Parse certificates for each domain
                certificates = parse_certificates(data)

                for certificate in certificates:
                    total_certificates += 1
                    missing_fields = check_for_missing_fields(certificate,logger)
                    check_if_certificate_is_self_signed(certificate,logger)
                    validation_level_counter(certificate.validation_level)



                    # stats
                    unique_missing = set(missing_fields)


                    for field in unique_missing:

                        len_unique_missing = len(unique_missing)
                        missing_count_dist[len_unique_missing] += 1

                        field_missing_count[field] += 1

                    domain_missing_count[certificate.subject_dn].append(len(unique_missing))



                json_data.append(data)
        except json.JSONDecodeError as e:
            print(f"Error reading {file_path}: {e}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    print(f"Number of non-certificate domains: {non_certificate_domain_counter}")
    print(f"Total domains with certificates: {domains_with_certs}")
    print(f"Total domains processed: {non_certificate_domain_counter + domains_with_certs}")

    print(f"Total certificates processed: {total_certificates}")

    # Write stats to CSV files
    write_field_stats_csv(field_missing_count)
    write_domain_stats_csv(domain_missing_count)
    write_missing_count_dist_csv(missing_count_dist)
    write_domain_detail_csv(domain_missing_count)
    write_validation_level_csv(validation_level_counts)
    write_overview_csv(
        non_certificate_domain_counter,
        domains_with_certs,
        total_certificates,
    )

    return json_data


def main():
    logger = custom_logger()
    logger.info("Starting analysis of blocked Netlas certificates...")
    read_netlas_certs_blocked(logger)
    logger.info("Completed analysis of blocked Netlas certificates.")

if __name__ == "__main__":
    main()