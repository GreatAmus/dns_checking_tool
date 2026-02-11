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

        "VALIDATION_UNAVAILABLE": "Install the Python 'cryptography' package (and redeploy) so the checker can validate DNSSEC signatures.",
        "DNSSEC_NOT_ENABLED": "No DS record exists at the parent, so the zone is delegated insecure. If you want DNSSEC enabled, publish DS at your registrar/parent.",

        # Informational
        "WILDCARD_PRESENT": "A wildcard may exist (random name returned data). Ensure wildcard behavior is intended; DNSSEC can still be correct.",

        "DNSKEY_RRSIG_INVALID": (
        "DNSKEY RRset signatures did not validate. Ensure authoritative servers publish "
        "the correct DNSKEY RRset and matching RRSIGs, and that the zone is signed consistently "
        "across all nameservers. Check for stale signatures or mismatched keys during rollover."
        ),

        "SOA_RRSIG_INVALID": (
        "SOA RRset signatures did not validate. Ensure the zone is properly signed and that "
        "authoritative servers serve consistent SOA+RRSIG. Look for stale/expired signatures "
        "or inconsistent zone data between nameservers."
        ),

        "NS_RRSIG_INVALID": (
            "NS RRset signatures did not validate. Ensure authoritative servers serve consistent NS+RRSIG "
            "and that signatures are current (not expired) and match the active DNSKEY set."
        ),
        
        "VALIDATION_UNAVAILABLE": (
        "Install the Python 'cryptography' package (and redeploy) so the checker can validate DNSSEC signatures."
        ),
        "DNSKEY_RRSIG_INVALID": "DNSKEY RRset signatures did not validate. Ensure the zone is signed consistently across all authoritative servers and that DNSKEY/RRSIG sets are current and match the active keys.",
        "SOA_RRSIG_INVALID": "SOA RRset signatures did not validate. Check for stale/expired signatures or inconsistent zone data across authoritative servers.",
        "NS_RRSIG_INVALID": "NS RRset signatures did not validate. Ensure NS RRset and its signatures are consistent and current on all authoritative servers.",
        "VALIDATION_UNAVAILABLE": "Install the Python 'cryptography' package in the deployment so DNSSEC signature validation can run.",
        "NO_NAMESERVERS": "The zone has no NS records (lame/invalid delegation). Fix delegation so NS records exist at the parent.",
        "NS_LOOKUP_FAILED": "NS lookup failed. Verify the zone exists and that recursive resolution is working; check for SERVFAIL/NXDOMAIN.",
        "AUTH_NS_IP_LOOKUP_FAILED": "Nameservers exist but did not resolve to IPs. Fix glue/NS hostnames or DNS for the nameserver names.",

        # CAA recommendations
        "CAA_NONE": (
            "No CAA records were found. If you want to restrict which CAs may issue certificates for this domain, "
            "add CAA records (for example, authorize your preferred CA). If you do not want restrictions, no action is needed."
        ),

        "CAA_PRESENT": (
            "CAA records are present. Ensure they authorize all CAs and certificate types you rely on "
            "(non-wildcard and wildcard if applicable)."
        ),

        "CAA_BLOCKS_ISSUANCE": (
            "Your CAA policy does not authorize non-wildcard issuance. "
            "To allow issuance, add at least one CAA 'issue' record for an approved CA, for example: "
            "CAA 0 issue \"digicert.com\" (or your chosen CA). If you intended to block issuance, no action is needed."
        ),

        "CAA_BLOCKS_WILDCARDS": (
            "Your CAA policy restricts wildcard issuance. "
            "To allow wildcard certificates, add an 'issuewild' record authorizing a CA, for example: "
            "CAA 0 issuewild \"digicert.com\". If 'issuewild' is not present, wildcard authorization falls back to 'issue'."
        ),

        "CAA_DIGICERT_NOT_ALLOWED": (
            "CAA records exist but do not authorize DigiCert for non-wildcard issuance. "
            "If you want DigiCert (or a DigiCert brand) to be able to issue, add an 'issue' authorization for one of DigiCert’s "
            "accepted values (e.g., \"digicert.com\", \"thawte.com\", \"geotrust.com\", \"rapidssl.com\")."
        ),

        "CAA_DIGICERT_WILDCARD_NOT_ALLOWED": (
            "CAA records exist but do not authorize DigiCert for wildcard issuance. "
            "If you want DigiCert to issue wildcards, add an 'issuewild' authorization for a DigiCert accepted value "
            "(or ensure the fallback 'issue' policy includes DigiCert)."
        ),
        "CAA_DNSSEC_VALIDATION_CRITICAL": (
            "CAA lookups could not be confirmed as DNSSEC-validated (or returned SERVFAIL/TIMEOUT/ERROR) via the validating resolver. "
            "For CA-style behavior, treat this as a hard stop: do not rely on the CAA result until DNSSEC validation succeeds. "
            "Fix DNSSEC breakage (DS/DNSKEY/RRSIG/NSEC/NSEC3 issues), authoritative availability problems, or validating resolver configuration."
        ),
        "CAA_LOOKUP_FAILED": (
            "CAA lookup failed (SERVFAIL/TIMEOUT/ERROR) using the validating resolver. "
            "For CA-style issuance, treat this as a hard stop: do not treat it as permission to issue. "
            "Fix validating resolver reachability/config, or authoritative/DNSSEC issues causing validation failure."
        ),
    }


    @classmethod
    def recommend(cls, issue: str) -> str:
        return cls._MAP.get(issue, "No recommendation available for this issue yet.")
