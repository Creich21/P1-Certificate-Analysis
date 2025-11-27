# cert_analyzer/parser_netlas.py
from typing import Any, Dict, List

from .models.common import (
    Signature,
    SignatureAlgorithm,
    NameEntity,
    Validity,
    Fingerprints,
)
from .models.extensions import (
    Extensions,
    CertificatePolicy,
    KeyUsage,
    ExtendedKeyUsage,
    BasicConstraints,
    AuthorityInfoAccess,
    SubjectAltName,
    SignedCertificateTimestamp,
)
from .models.certificates import Certificate
from .models.results import (
    Highlight,
    CertificateData,
    CertificateItem,
    NetlasResult,
)

from .analysis.basic_analysis import compute_certificate_features
import csv
from pathlib import Path


def _parse_name_entity(obj: Dict[str, Any]) -> NameEntity:
    return NameEntity(
        country=obj.get("country"),
        organization=obj.get("organization"),
        common_name=obj.get("common_name"),
    )


def _parse_signature_algorithm(obj: Dict[str, Any]) -> SignatureAlgorithm:
    return SignatureAlgorithm(
        name=obj["name"],
        oid=obj["oid"],
    )


def _parse_signature(obj: Dict[str, Any]) -> Signature:
    return Signature(
        valid=obj.get("valid", False),
        signature_algorithm=_parse_signature_algorithm(obj["signature_algorithm"]),
        value=obj.get("value", ""),
        self_signed=obj.get("self_signed", False),
    )


def _parse_validity(obj: Dict[str, Any]) -> Validity:
    return Validity(
        length=obj["length"],
        start=obj["start"],
        end=obj["end"],
    )


def _parse_fingerprints(cert: Dict[str, Any]) -> Fingerprints:
    return Fingerprints(
        md5=cert.get("fingerprint_md5"),
        sha1=cert.get("fingerprint_sha1"),
        sha256=cert.get("fingerprint_sha256"),
        tbs=cert.get("tbs_fingerprint"),
        tbs_noct=cert.get("tbs_noct_fingerprint"),
        spki_subject=cert.get("spki_subject_fingerprint"),
    )


def _parse_extensions(obj: Dict[str, Any]) -> Extensions:
    if obj is None:
        return Extensions(extra=None)

    policies = None
    if "certificate_policies" in obj:
        policies = [CertificatePolicy(id=p["id"]) for p in obj["certificate_policies"]]

    key_usage = None
    if "key_usage" in obj:
        ku = obj["key_usage"]
        key_usage = KeyUsage(
            digital_signature=ku.get("digital_signature"),
            certificate_sign=ku.get("certificate_sign"),
            crl_sign=ku.get("crl_sign"),
            key_encipherment=ku.get("key_encipherment"),
            value=ku.get("value"),
        )

    eku = None
    if "extended_key_usage" in obj:
        e = obj["extended_key_usage"]
        eku = ExtendedKeyUsage(
            client_auth=e.get("client_auth"),
            server_auth=e.get("server_auth"),
        )

    bc = None
    if "basic_constraints" in obj:
        b = obj["basic_constraints"]
        bc = BasicConstraints(
            is_ca=b["is_ca"],
            max_path_len=b.get("max_path_len"),
        )

    aia = None
    if "authority_info_access" in obj:
        a = obj["authority_info_access"]
        aia = AuthorityInfoAccess(
            issuer_urls=a.get("issuer_urls"),
        )

    san = None
    if "subject_alt_name" in obj:
        s = obj["subject_alt_name"]
        san = SubjectAltName(
            dns_names=s.get("dns_names"),
        )

    scts = None
    if "signed_certificate_timestamps" in obj:
        scts = [
            SignedCertificateTimestamp(
                log_id=s["log_id"],
                signature=s["signature"],
                version=s["version"],
                timestamp=s["timestamp"],
            )
            for s in obj["signed_certificate_timestamps"]
        ]

    return Extensions(
        crl_distribution_points=obj.get("crl_distribution_points"),
        subject_key_id=obj.get("subject_key_id"),
        certificate_policies=policies,
        key_usage=key_usage,
        authority_key_id=obj.get("authority_key_id"),
        authority_info_access=aia,
        basic_constraints=bc,
        extended_key_usage=eku,
        subject_alt_name=san,
        signed_certificate_timestamps=scts,
        extra=None,  # or obj if you want raw copy
    )


def _parse_certificate(cert: Dict[str, Any]) -> Certificate:
    # chain first (recursive)
    chain = None
    if "chain" in cert:
        chain = [_parse_certificate(c) for c in cert["chain"]]

    subject = _parse_name_entity(cert["subject"]) if "subject" in cert else None
    issuer = _parse_name_entity(cert["issuer"]) if "issuer" in cert else None

    certificate = Certificate(
        issuer_dn=cert["issuer_dn"],
        subject_dn=cert["subject_dn"],
        serial_number=cert["serial_number"],
        version=cert["version"],
        validation_level=cert.get("validation_level"),
        src=cert.get("src"),
        redacted=cert.get("redacted", False),
        subject=subject,
        issuer=issuer,
        fingerprints=_parse_fingerprints(cert),
        signature=_parse_signature(cert["signature"]),
        signature_algorithm=_parse_signature_algorithm(cert["signature_algorithm"]),
        validity=_parse_validity(cert["validity"]),
        extensions=_parse_extensions(cert.get("extensions")),
        names=cert.get("names"),
        chain=chain,
    )

    certificate.features = compute_certificate_features(certificate)


    return certificate





def parse_netlas_result(raw: Dict[str, Any],searching_domain) -> NetlasResult:
    items: List[CertificateItem] = []

    for item in raw["items"]:
        h = item.get("highlight", {})

        certificate_subject_dn = h.get("certificate.subject_dn", None)

        #Extracting only the CN matching the searching domain
        if certificate_subject_dn:
            cn = certificate_subject_dn.split(",")[0].strip()
            if cn != f"CN={searching_domain}":
                continue
        print(f"Parsing certificate: {certificate_subject_dn}")

        highlight = Highlight(
            certificate_subject_dn=h.get("certificate.subject_dn"),
        )

        cert_dict = item["data"]["certificate"]
        cert = _parse_certificate(cert_dict)

        data = CertificateData(
            last_updated=item["data"]["last_updated"],
            timestamp=item["data"]["@timestamp"],
            certificate=cert,
        )

        items.append(
            CertificateItem(
                highlight=highlight,
                data=data,
                index_id=item["index_id"],
            )
        )

    return NetlasResult(items=items)
