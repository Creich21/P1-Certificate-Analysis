from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class CertificatePolicy:
    id: str


@dataclass
class KeyUsage:
    digital_signature: Optional[bool] = None
    certificate_sign: Optional[bool] = None
    crl_sign: Optional[bool] = None
    key_encipherment: Optional[bool] = None
    value: Optional[int] = None   # raw bitmask


@dataclass
class ExtendedKeyUsage:
    client_auth: Optional[bool] = None
    server_auth: Optional[bool] = None


@dataclass
class BasicConstraints:
    is_ca: bool
    max_path_len: Optional[int] = None


@dataclass
class AuthorityInfoAccess:
    issuer_urls: Optional[List[str]] = None


@dataclass
class SubjectAltName:
    dns_names: Optional[List[str]] = None


@dataclass
class SignedCertificateTimestamp:
    log_id: str
    signature: str
    version: int
    timestamp: int


@dataclass
class Extensions:
    crl_distribution_points: Optional[List[str]] = None
    subject_key_id: Optional[str] = None
    certificate_policies: Optional[List[CertificatePolicy]] = None
    key_usage: Optional[KeyUsage] = None
    authority_key_id: Optional[str] = None
    authority_info_access: Optional[AuthorityInfoAccess] = None
    basic_constraints: Optional[BasicConstraints] = None
    extended_key_usage: Optional[ExtendedKeyUsage] = None
    subject_alt_name: Optional[SubjectAltName] = None
    signed_certificate_timestamps: Optional[List[SignedCertificateTimestamp]] = None

    # for future-proofing: keep any unknown stuff too
    extra: Optional[Dict[str, Any]] = None
