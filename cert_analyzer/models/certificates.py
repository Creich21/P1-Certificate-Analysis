# cert_analyzer/models/certificate.py
from dataclasses import dataclass
from typing import List, Optional

from .common import (
    Signature,
    SignatureAlgorithm,
    NameEntity,
    Validity,
    Fingerprints,
)
from .extensions import Extensions
from .features import CertificateFeatures


@dataclass
class Certificate:
    issuer_dn: str
    subject_dn: str
    serial_number: str
    version: int
    validation_level: Optional[str]
    src: Optional[str]          
    redacted: bool


    subject: Optional[NameEntity]
    issuer: Optional[NameEntity]

    fingerprints: Fingerprints
    signature: Signature
    signature_algorithm: SignatureAlgorithm
    validity: Validity
    extensions: Extensions

    # SANs / names
    names: Optional[List[str]] = None

    # chain of issuers (for leaf certs)
    chain: Optional[List["Certificate"]] = None

    #features
    features: Optional["CertificateFeatures"] = None
