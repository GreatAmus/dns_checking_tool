class Recommendations:
    _MAP = {
        # Delegation / DS
        "PARENT_UNSIGNED": "Parent zone appears unsigned. If you expect DNSSEC validation, ensure the parent publishes DNSKEY and supports DNSSEC.",
        "PARENT_DS_QUERY_FAILED": "Could not query DS from the parent. Check connectivity to parent authoritative servers or try again; if persistent, validate parent NS availability.",
        "DS_MISSING": "Publish a DS record at your registrar/parent for the active KSK (DNSKEY with SEP bit). Without DS, validators treat the child as insecure.",
        "DS_NXDOMAIN": "Parent responded NXDOMAIN for DS lookup. Confirm the delegation exists and that you are querying the correct zone name.",
        "DS_MISMATCH": "Update the DS at the registrar/parent to match the currently published KSK DNSKEY. If you rolled keys, ensure DS was updated and old DS removed after rollover.",
        "DS_COMPUTE_FAILED": "DS could not be computed from the DNSKEY. Ensure you use a supported algorithm/digest (typically SHA-256 or SHA-384) and that DNSKEY is correct.",
        "DNSKEY_QUERY_FAILED": "Authoritative DNSKEY query failed. Ensure the zone apex publishes DNSKEY and that authoritative servers respond to DNSSEC (EDNS + DO).",
        "DNSKEY_NODATA": "Publish DNSKEY at the zone apex and enable DNSSEC signing on your DNS provider. Ensure the DNSKEY RRset is returned from all authoritative nameservers.",

        # Signatures
        "DNSKEY_RRSIG_MISSING": "Sign the DNSKEY RRset (KSK should sign it). Ensure your signer publishes RRSIG(DNSKEY).",
        "DNSKEY_RRSIG_INVALID": "RRSIG(DNSKEY) is invalid. Re-sign the zone and confirm the correct keys are active and your signer clock is accurate.",
        "SOA_RRSIG_MISSING": "Sign the SOA RRset and publish RRSIG(SOA). Enable signing for the zone and ensure signatures are published.",
        "SOA_RRSIG_INVALID": "RRSIG(SOA) failed validation. Re-sign the zone; check signer clock skew and signature expiration/inception windows.",
        "NS_RRSIG_MISSING": "Sign the NS RRset at the apex. Ensure the signer includes RRSIG(NS) and that authoritative servers serve it consistently.",
        "NS_RRSIG_INVALID": "RRSIG(NS) failed validation. Re-sign the zone; ensure NS RRset is identical across all auths and signatures are current.",

        # Denial of existence
        "DENIAL_PROOF_MISSING": "NXDOMAIN responses must include signed NSEC or NSEC3 proofs. Ensure NSEC/NSEC3 is enabled and published on authoritative servers.",
        "DENIAL_RRSIG_MISSING": "Denial proofs exist but are unsigned. Ensure the signer is generating and publishing RRSIG for NSEC/NSEC3 records.",
        "NX_PROBE_FAILED": "Non-existence probe failed. Check resolver reachability and that authoritative servers respond reliably.",
        "NX_PROBE_QUERY_FAILED": "Could not retrieve the full NXDOMAIN response message. Check UDP/TCP reachability and firewall rules.",

        # Informational
        "WILDCARD_PRESENT": "A wildcard may exist (random name returned data). Ensure wildcard behavior is intended; DNSSEC can still be correct.",
    }

    @classmethod
    def recommend(cls, issue: str) -> str:
        return cls._MAP.get(issue, "No recommendation available for this issue yet.")
