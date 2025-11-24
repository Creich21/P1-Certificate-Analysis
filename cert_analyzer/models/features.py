import datetime
from dataclasses import dataclass
from typing import Optional

@dataclass
class CertificateFeatures:
    # Time-related features
    days_until_expiry: Optional[int] = None
    valid_time_so_far_days: Optional[int] = None
    has_expired: Optional[bool] = None

    # Serial number features
    serial_number_length: Optional[int] = None

    # SAN-related features
    num_san_dns_names: int = 0
    san_has_wildcard_dns: bool = False
    san_has_exact_subdomain_dns: bool = False

    # Trust / PKI flags
    is_trusted_certificate: Optional[bool] = None
    key_cert_sign: Optional[bool] = None
