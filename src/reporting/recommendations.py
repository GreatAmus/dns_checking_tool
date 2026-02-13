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
        # DNS Health / misconfig recommendations
        "NO_AUTHORITATIVE_REACHABLE": (
            "None of the delegated authoritative nameservers responded authoritatively for this zone. "
            "Verify delegation at the registrar/parent zone, confirm the NS hostnames are correct, and ensure the "
            "listed nameservers are configured to serve the zone and are reachable on UDP/TCP 53."
        ),
        "NS_UNREACHABLE": (
            "At least one authoritative nameserver timed out or could not be reached. "
            "Check firewall rules and allow inbound UDP/TCP 53 to that server, confirm the IP is correct, "
            "and verify the service is running and reachable from the public internet."
        ),
        "NS_PARTIAL_OUTAGE": (
            "Some authoritative nameservers are unhealthy. Fix or remove broken nameservers from the delegation "
            "to avoid intermittent resolution failures. All NS should consistently answer authoritatively."
        ),
        "LAME_DELEGATION": (
            "A delegated nameserver is responding but is not authoritative for the zone (lame delegation). "
            "Ensure the zone is loaded on that server, the server is configured as authoritative for the zone, "
            "and the NS listed at the parent matches the servers actually hosting the zone."
        ),
        "NS_NAME_NO_ADDRESS": (
            "A delegated nameserver hostname did not resolve to an A/AAAA record. "
            "Fix the nameserver hostname's DNS (publish A/AAAA), correct the NS name in delegation, "
            "or ensure glue exists if the NS is in-bailiwick (e.g., ns1.example.com)."
        ),
        "NS_PARENT_CHILD_MISMATCH": (
            "The parent delegation NS set differs from the zone's authoritative NS RRset. "
            "Update either the registrar/parent delegation or the zone's NS RRset so they match, "
            "and ensure all authoritative servers publish the same NS RRset."
        ),
        "NS_INCONSISTENT": (
            "Authoritative servers disagree on zone data (often NS RRset or other core records). "
            "Sync zone contents across all authoritative servers (fix stale secondaries, notify/transfer, "
            "or correct the hidden primary) so every authoritative server serves identical data."
        ),
        "APEX_CNAME": (
            "The zone apex should not be a CNAME in typical DNS hosting setups. "
            "Replace the apex CNAME with supported alternatives (A/AAAA records, or ALIAS/ANAME flattening "
            "if your DNS provider supports it)."
        ),
        "EDNS_BROKEN": (
            "The authoritative server appears to mishandle EDNS(0). "
            "Update the DNS server software, check middleboxes/firewalls that may drop EDNS packets, "
            "and confirm the server supports modern EDNS behavior."
        ),
        "TCP_FALLBACK_BROKEN": (
            "UDP responses are truncating, but TCP fallback is failing. "
            "Ensure TCP/53 is allowed through firewalls/load balancers, and that the authoritative server "
            "is configured to accept TCP DNS queries."
        ),
        "UDP_RESPONSE_LARGE": (
            "DNS responses are large and may fragment, causing failures behind some networks. "
            "Reduce response size (fewer/shorter TXT/CAA records), consider removing unnecessary records, "
            "and ensure TCP/53 works reliably for fallback."
        ),
        # DCV / ACME recommendations
        "HTTP01_PORT80_CLOSED": (
            "HTTP-01 requires port 80 to be reachable from the public internet. "
            "Open inbound TCP/80 on firewalls/security groups/load balancers, and ensure the domain resolves to that server."
        ),
        "HTTP01_FETCH_FAILED": (
            "The HTTP-01 probe failed. Ensure the domain resolves correctly and that your web server responds on port 80. "
            "Check firewalls, routing, and whether the server is up."
        ),
        "HTTP01_BLOCKED_PATH": (
            "The path /.well-known/acme-challenge/ appears blocked (401/403). "
            "Allow unauthenticated GETs to that path and configure WAF/CDN rules to bypass blocking for ACME challenges."
        ),
        "HTTP01_SERVER_ERROR": (
            "The server returned 5xx during HTTP-01 probing. Fix backend errors and ensure the endpoint is stable before validating."
        ),
        "HTTP01_REDIRECT_DIFFERENT_HOST": (
            "Avoid redirecting ACME challenge requests to a different hostname. "
            "Keep HTTP-01 validation on the same hostname, or ensure the target hostname also serves the correct challenge content."
        ),
        "HTTP01_REDIRECT_LOOP": (
            "A redirect loop was detected. Fix your HTTP->HTTPS or canonical-host redirect rules so the challenge URL resolves cleanly."
        ),

        "DNS01_TXT_MISSING": (
            "DNS-01 requires a TXT record at _acme-challenge.<domain>. Create that TXT record with the token provided by your ACME client/CA."
        ),
        "DNS01_TXT_MISMATCH": (
            "A TXT record exists at _acme-challenge.<domain>, but it doesn't match the expected token. "
            "Update the TXT value exactly as provided and remove outdated tokens."
        ),
        "DNS01_TXT_MULTIPLE": (
            "Multiple TXT values exist at _acme-challenge.<domain>. Remove old/unused challenge tokens to avoid confusion."
        ),
        "DNS01_NXDOMAIN": (
            "The name _acme-challenge.<domain> does not exist. Create the TXT record (your DNS provider will create the name automatically)."
        ),
        "DNS01_TIMEOUT": (
            "TXT lookup timed out. Check authoritative DNS availability and any DNS/firewall issues. Try again, or reduce DNS provider latency issues."
        ),
        "DNS01_QUERY_FAILED": (
            "DNS-01 TXT lookup failed. Verify the domain exists, that DNS is functioning normally, and try again."
        ),

        "ALPN01_PORT443_CLOSED": (
            "TLS-ALPN-01 requires port 443 to be reachable from the public internet. "
            "Open inbound TCP/443 on firewalls/security groups/load balancers, and ensure the domain resolves to that server."
        ),
        "ALPN01_TLS_HANDSHAKE_FAILED": (
            "TLS handshake failed on port 443. Fix TLS configuration (cert/key, protocols, SNI routing) so a basic TLS connection succeeds."
        ),
        "ALPN01_ALPN_UNSUPPORTED": (
            "TLS-ALPN-01 requires ALPN support. Ensure your TLS stack/web server supports ALPN and is not stripping ALPN via a proxy/load balancer."
        ),
        "ALPN01_TIMEOUT": (
            "TLS handshake timed out. Check network reachability, firewall rules, and whether the server is overloaded."
        ),
        "ALPN01_ERROR": (
            "Unexpected TLS-ALPN-01 probe error. Review server logs and network path; ensure TLS is configured correctly."
        ),
        # Website-change (ACME + non-ACME readiness)
        # Website-change (ACME + non-ACME readiness)
        "WEBSITE_CHANGE_PORT80_CLOSED": (
            "Website-change validation requires HTTP reachability. Open inbound TCP/80 and ensure the domain routes to the correct server."
        ),
        "WEBSITE_CHANGE_FETCH_FAILED": (
            "The website-change probe failed. Ensure the site responds on port 80 and that routing/firewalls/CDNs are not blocking the request."
        ),
        "WEBSITE_CHANGE_PATH_BLOCKED": (
            "The validation path returned 401/403. Allow unauthenticated GET access under the required .well-known path "
            "(e.g., /.well-known/acme-challenge/ or /.well-known/pki-validation/) and adjust WAF/CDN rules accordingly."
        ),
        "WEBSITE_CHANGE_NOT_FOUND": (
            "The expected validation file/token was not found (404). Publish the CA/ACME-provided token at the exact required URL path."
        ),
        "WEBSITE_CHANGE_SERVER_ERROR": (
            "The server returned 5xx while probing the validation path. Fix backend errors and make the endpoint stable before validating."
        ),

        # BR 3.2.2.4.7 DNS Change (generic)
        "DNS_CHANGE_BAD_TYPE": (
            "dns_change_type must be TXT or CNAME. Use the record type specified by your CA for DNS Change validation."
        ),
        "DNS_CHANGE_TXT_MISSING": (
            "Create the required TXT record at the CA-specified name and publish the CA-provided token exactly."
        ),
        "DNS_CHANGE_TXT_MISMATCH": (
            "Update the TXT record value to exactly match the CA-provided token, and remove outdated values if necessary."
        ),
        "DNS_CHANGE_TXT_MULTIPLE": (
            "Multiple TXT values were found. Remove outdated validation tokens to avoid confusion."
        ),
        "DNS_CHANGE_NXDOMAIN": (
            "The CA-specified validation name does not exist. Create the required TXT/CNAME record for DNS Change validation."
        ),
        "DNS_CHANGE_TIMEOUT": (
            "DNS query timed out. Check authoritative DNS availability, reachability, and resolver issues."
        ),
        "DNS_CHANGE_QUERY_FAILED": (
            "DNS Change lookup failed. Verify the record exists and DNS is functioning normally."
        ),
        "DNS_CHANGE_CNAME_MISSING": (
            "Create the required CNAME record at the CA-specified validation name."
        ),
        "DNS_CHANGE_CNAME_MISMATCH": (
            "Update the CNAME target to exactly match the CA-provided canonical authorization value."
        ),

        # BR 3.2.2.4.22 Persistent DCV TXT (generic)
        "PERSISTENT_TXT_TXT_MISSING": (
            "Create the Persistent DCV TXT record at the required name with the persistent value expected by your CA."
        ),
        "PERSISTENT_TXT_TXT_MISMATCH": (
            "Update the Persistent DCV TXT record so it matches the expected persistent value."
        ),
        "PERSISTENT_TXT_TXT_MULTIPLE": (
            "Multiple TXT values were found. Remove outdated/incorrect persistent values so only the intended value remains."
        ),
        "PERSISTENT_TXT_NXDOMAIN": (
            "The persistent TXT name does not exist. Create the required TXT record under your domain."
        ),
        "PERSISTENT_TXT_TIMEOUT": (
            "Timed out fetching the persistent TXT record. Check DNS availability and authoritative server health."
        ),
        "PERSISTENT_TXT_QUERY_FAILED": (
            "Lookup for the persistent TXT record failed. Verify the record exists and DNS is functioning normally."
        ),

        # BR 3.2.2.5.1 Website change for IP
        "IP_WEBSITE_CHANGE_BAD_IP": (
            "Provide a valid IPv4/IPv6 address."
        ),
        "IP_WEBSITE_CHANGE_FETCH_FAILED": (
            "The IP-based website-change probe failed. Ensure the service is reachable on HTTP and not blocked by firewalls/security groups."
        ),
        "IP_WEBSITE_CHANGE_BLOCKED": (
            "The IP-based validation path returned 401/403. Allow unauthenticated GET access to the CA-specified validation URL path."
        ),
        "IP_WEBSITE_CHANGE_SERVER_ERROR": (
            "The server returned 5xx for the IP-based validation path. Fix backend errors and ensure the endpoint is stable."
        ),

        # BR 3.2.2.5.8 Reverse namespace persistent TXT
        "REVERSE_PTXT_BAD_IP": (
            "Provide a valid IPv4/IPv6 address."
        ),
        "REVERSE_PTXT_TXT_MISSING": (
            "No TXT record was found at the reverse name. You must have control of reverse DNS (in-addr.arpa/ip6.arpa) for this IP. "
            "Work with your ISP/cloud provider to publish the required TXT record."
        ),
        "REVERSE_PTXT_TXT_MISMATCH": (
            "Update the reverse-namespace TXT record so it matches the expected persistent value. This typically requires ISP/provider support."
        ),
        "REVERSE_PTXT_TIMEOUT": (
            "Timed out querying the reverse-namespace TXT record. Check reverse DNS authoritative availability and reachability."
        ),
        "REVERSE_PTXT_QUERY_FAILED": (
            "Reverse-namespace TXT lookup failed. Verify reverse DNS is delegated and that TXT records are supported/published by the reverse DNS operator."
        ),

    }


    @classmethod
    def recommend(cls, issue: str) -> str:
        return cls._MAP.get(issue, "No recommendation available for this issue yet.")
