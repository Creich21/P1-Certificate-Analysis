from dataclasses import dataclass
from typing import Optional, List

from .certificates import Certificate


@dataclass
class Highlight:
    certificate_subject_dn: Optional[str] = None


@dataclass
class CertificateData:
    last_updated: str
    timestamp: str  # @timestamp
    certificate: Certificate


@dataclass
class CertificateItem:
    highlight: Highlight
    data: CertificateData
    index_id: int



@dataclass
class NetlasResult:
    items: List[CertificateItem]
