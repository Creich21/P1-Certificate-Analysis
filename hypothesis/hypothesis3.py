#Hypothesis 3. It is expected to see a correlation between missing information fields and a high likelihood of phishing
#Also checks if certificate is self-signed or not
# in P1-Certificate-Analysis run python3 -m hypothesis.hypothesis3
import datetime
import json
from pathlib import Path
import sys
from colorama import Fore, Style
from cert_analyzer.analysis.basic_analysis import _parse_iso_z, days_until_expiry, is_expired


project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from typing import Any, Dict, List
from cert_analyzer.models.results import CertificateItem
from cert_analyzer.models.features import CertificateFeatures

from cert_analyzer.models.results import Highlight
from cert_analyzer.models.certificates import Certificate



def get_filename_from_path(file_path: Path) -> str:
    """Extract just the filename from a full path"""
    return file_path.name

def check_if_json_is_empty(f, json_data, message:str="") -> bool:
    if json_data is None or json_data == []:
        #set_alert(Fore.RED + f"Empty JSON data in file {get_filename_from_path(f)}. {message}" + Style.RESET_ALL)
        return True
    return False

def set_alert(message:str=""):
    """This functions is enabled when a suspicious certificate is found.
    It sets an alert when detects a certificate with missing fields"""
    print(f"ALERT: {message}")
    #open("alerts.log", "a").write(f"ALERT: {message}\n")





def get_blocked_certs_dir() -> Path:
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    data_dir = project_root / "data"
    blocked_dir = data_dir / "netlas_certs_blocked_no_duplicates"
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
                set_alert(Fore.RED + f"Certificate {certificate.subject_dn} is missing SAN information." + Style.RESET_ALL)


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

def check_for_missing_fields(certificate: Certificate) -> None:
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

        set_alert(prefix + Fore.RED + fields_str + Style.RESET_ALL)

def check_if_certificate_is_self_signed(certificate: Certificate) -> None:
    sig = certificate.signature or {}
    is_self_signed = sig.get("self_signed")

    print(is_self_signed)

    if is_self_signed:
        print(
            Fore.YELLOW
            + f"Certificate {certificate.subject_dn} is self-signed."
            + Style.RESET_ALL
        )

    


def read_netlas_certs_blocked():
    blocked_dir = get_blocked_certs_dir()
    if not validate_directory(blocked_dir):
        return []
    

    json_data = []
    non_certificate_domain_counter = 0

    for file_path in blocked_dir.glob("*.json"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                file_name = get_filename_from_path(file_path)
                print(f"Processing file: {file_name}")

                # Check how many of domains have no certificates
                if check_if_json_is_empty(file_path,data):
                    non_certificate_domain_counter += 1
                    continue

                certificates = parse_certificates(data)
                for certificate in certificates:
                    check_for_missing_fields(certificate)
                    check_if_certificate_is_self_signed(certificate)

                json_data.append(data)
        except json.JSONDecodeError as e:
            print(f"Error reading {file_path}: {e}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    print(f"Number of non-certificate domains: {non_certificate_domain_counter}")
    return json_data


def main():
    read_netlas_certs_blocked()

if __name__ == "__main__":
    main()