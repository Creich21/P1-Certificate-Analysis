# cert_analyzer/analysis/basic.py

from datetime import datetime, timezone
from typing import Counter, Dict

from ..models.certificates import Certificate
from ..models.features import CertificateFeatures
from ..models.results import NetlasResult


def _parse_iso_z(dt_str: str) -> datetime:
    """Parse ISO8601 datetime with trailing 'Z' into aware UTC datetime."""
    # Example: "2025-07-11T20:58:13Z"
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def is_expired(cert: Certificate) -> bool:
    """Return True if certificate is already expired."""
    v = cert.validity

    # Support both: object with .end and dict with ["end"]
    if isinstance(v, dict):
        end_value = v.get("end")
    else:
        end_value = getattr(v, "end", None)

    if not end_value:
        # Decide policy: treat as expired or raise
        raise ValueError("validity.end is missing")

    end = _parse_iso_z(end_value)
    return datetime.now(timezone.utc) > end 



def days_until_expiry(cert: Certificate) -> int:
    """Return number of days until expiry (negative if already expired)."""
    v = cert.validity

    # Support both: object with .end and dict with ["end"]
    if isinstance(v, dict):
        end_value = v.get("end")
    else:
        end_value = getattr(v, "end", None)

    if not end_value:
        # Decide what you want here: raise or use a default
        raise ValueError("validity.end is missing")

    end = _parse_iso_z(end_value)
    delta = end - datetime.now(timezone.utc)
    return delta.days

# def days_until_expiry(cert: Certificate) -> int:
#     """Return number of days until expiry (negative if already expired)."""
#     end = _parse_iso_z(cert.validity.end)
#     delta = end - datetime.now(timezone.utc)
#     return delta.days

def compute_certificate_features(cert: Certificate) -> CertificateFeatures:
    """Compute and return features for a given certificate."""

    # SAN-related features
    san = cert.extensions.subject_alt_name.dns_names if cert.extensions.subject_alt_name else []
    num_san_dns_names = len(san)
    san_has_wildcard_dns = any(n.startswith("*.") for n in san)
    san_has_exact_subdomain_dns = any("." in n and not n.startswith("*.") for n in san)

    # Time-related features
    days_left = days_until_expiry(cert)
    valid_time_so_far_days = (datetime.now(timezone.utc) - _parse_iso_z(cert.validity.start)).days
    has_expired = is_expired(cert)

    # PKI-related features
    bc = cert.extensions.basic_constraints
    key_usage = cert.extensions.key_usage
    is_trusted_certificate = bc.is_ca if bc else None
    key_cert_sign = key_usage.certificate_sign if key_usage else None

    return CertificateFeatures(
        days_until_expiry=days_left,
        valid_time_so_far_days=valid_time_so_far_days,
        has_expired=has_expired,
        serial_number_length=len(cert.serial_number),
        num_san_dns_names=num_san_dns_names,
        san_has_wildcard_dns=san_has_wildcard_dns,
        san_has_exact_subdomain_dns=san_has_exact_subdomain_dns,
        is_trusted_certificate=is_trusted_certificate,
        key_cert_sign=key_cert_sign,
    )


def print_certificate_summary(cert: Certificate) -> None:
    """Print a one-certificate human-readable summary."""
    print(f"Subject DN   : {cert.subject_dn}")
    print(f"Issuer DN    : {cert.issuer_dn}")
    print(f"Validation   : {cert.validation_level}")
    print(f"Valid from   : {cert.validity.start}")
    print(f"Valid until  : {cert.validity.end}")

    expired = is_expired(cert)
    days_left = days_until_expiry(cert)
    status = "EXPIRED" if expired else f"{days_left} days left"
    print(f"Status       : {status}")

    names = cert.names or []
    print(f"DNS names    : {', '.join(names) if names else '(none)'}")

    chain_len = len(cert.chain) if cert.chain else 0
    print(f"Chain length : {chain_len}")

    sig_algo = cert.signature_algorithm.name
    print(f"Signature alg: {sig_algo}")

    print("-" * 60)

    print("=" * 60)

def print_certificate_features(cert: Certificate) -> None:
    """Print the computed features of a certificate."""
    features = cert.features
    if not features:
        print("No features computed for this certificate.")
        return

    print(f"Number of SAN DNS names       : {features.num_san_dns_names}")
    print(f"Has wildcard SAN              : {features.san_has_wildcard_dns}")
    print(f"Has exact subdomain SAN       : {features.san_has_exact_subdomain_dns}")
    print(f"Days until expiry             : {features.days_until_expiry}")
    print(f"Valid time so far (days)      : {features.valid_time_so_far_days}")
    print(f"Is expired                    : {features.has_expired}")
    print(f"Length of serial number       : {features.serial_number_length}")
    print(f"Trusted certificate (is CA)   : {features.is_trusted_certificate}")
    print(f"Key Cert Sign                 : {features.key_cert_sign}")

    print("-" * 60)


def print_certificate_details(cert: Certificate) -> None:
    """Print detailed information about the certificate."""
    print(f"Subject DN        : {cert.subject_dn}")
    print(f"Issuer DN         : {cert.issuer_dn}")
    print(f"Serial Number     : {cert.serial_number}")
    print(f"Version           : {cert.version}")
    print(f"Validation Level  : {cert.validation_level}")
    print(f"Validity Period   : {cert.validity.start} to {cert.validity.end}")
    print(f"Signature Alg     : {cert.signature_algorithm.name}")
    print(f"Names             : {', '.join(cert.names) if cert.names else '(none)'}")
    print(f"Chain Length      : {len(cert.chain) if cert.chain else 0}")
    print(f"Extensions        : {cert.extensions}")
    print(f"Features         : {cert.features} ")
    print("-" * 60)


# def print_whole_certificate(cert: Certificate) -> None:
#     """Print the whole certificate object with nicer formatting (no emojis)."""
#     print("\n" + "=" * 80)
#     print("CERTIFICATE DETAILS")
#     print("=" * 80)

#     print("\nSUBJECT & ISSUER")
#     print(f"  Subject DN: {cert.subject_dn}")
#     print(f"  Issuer DN : {cert.issuer_dn}")

#     print("\nVALIDITY")
#     print(f"  Validity Period        : {cert.validity.start}  →  {cert.validity.end}")
#     print(f"  Length Seconds         : {cert.validity.length}")
#     print(f"  Days Until Expiry      : {days_until_expiry(cert)}")
#     print(f"  Valid Time So Far(days): {(datetime.now(timezone.utc) - _parse_iso_z(cert.validity.start)).days}")
#     print(f"  Certificate Has Expired: {is_expired(cert)}")

#     print("\nSIGNATURE & VERSION")
#     print(f"  Signature Algorithm : {cert.signature_algorithm.name}")
#     print(f"  Validation Level    : {cert.validation_level}")
#     print(f"  Version             : {cert.version}")
#     print(f"  Len of Serial Number: {len(cert.serial_number)}")

#     print("\nSUBJECT INFORMATION")
#     print(f"  Organization : {cert.subject.organization if cert.subject else 'N/A'}")
#     print(f"  Country      : {cert.subject.country if cert.subject else 'N/A'}")
#     print(f"  Common Name  : {cert.subject.common_name if cert.subject else 'N/A'}")

#     print("\nSUBJECT ALT NAMES (SAN)")
#     san = cert.extensions.subject_alt_name.dns_names if cert.extensions.subject_alt_name else None
#     print(f"  SAN DNS Names     : {san if san else 'N/A'}")
#     print(f"  Num SAN DNS Names : {len(san) if san else 0}")
#     print(f"  SAN Has Wildcard  : {any('*' in n for n in san) if san else False}")
#     print("  SAN Has Exact Subdomain DNS")

#     print("\nEXTENSIONS")
#     print(f"  Certificate Policies            : {cert.extensions.certificate_policies}")
#     print(f"  Authority Key Identifier        : {cert.extensions.authority_key_id}")
#     print(f"  Basic Constraints               : {cert.extensions.basic_constraints}")
#     print(f"  Key Usage                       : {cert.extensions.key_usage if cert.extensions.key_usage else 'N/A'}")
#     print(f"  Extended Key Usage              : {cert.extensions.extended_key_usage if cert.extensions.extended_key_usage else 'N/A'}")
#     print(f"  Subject Key Identifier          : {cert.extensions.subject_key_id if cert.extensions.subject_key_id else 'N/A'}")
#     print(f"  CRL Distribution Points         : {cert.extensions.crl_distribution_points if cert.extensions.crl_distribution_points else 'N/A'}")
#     print(f"  CT Signed Certificate Timestamps: {cert.extensions.signed_certificate_timestamps if cert.extensions.signed_certificate_timestamps else 'N/A'}")

#     print("\nTRUST / PKI FLAGS")
#     print(f"  BOOLEAN Trusted Certificates : {cert.extensions.basic_constraints.is_ca if cert.chain and cert.chain[0].extensions.basic_constraints else 'N/A'}")
#     print(f"  Key Cert Sign                : {cert.extensions.key_usage.certificate_sign if cert.extensions.key_usage else 'N/A'}")

#     print("\n" + "=" * 80 + "\n")

def analyze_netlas_result(result: NetlasResult) -> None:

    


    for item in result.items:
        cert = item.data.certificate
        print_certificate_details(cert)

    
    
