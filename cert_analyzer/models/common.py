from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class SignatureAlgorithm:
    name: str
    oid: str


@dataclass
class Signature:
    valid: bool
    signature_algorithm: SignatureAlgorithm
    value: str
    self_signed: bool


@dataclass
class NameEntity:
    country: Optional[List[str]] = None
    organization: Optional[List[str]] = None
    common_name: Optional[List[str]] = None


@dataclass
class Validity:
    length: int
    start: str
    end: str


@dataclass
class Fingerprints:
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    tbs: Optional[str] = None
    tbs_noct: Optional[str] = None
    spki_subject: Optional[str] = None
