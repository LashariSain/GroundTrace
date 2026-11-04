"""Benign-infrastructure filter for captured sandbox network sets.

A sandbox records every host a sample touched, which includes a great deal of
traffic the sample did not choose: OS update checks, certificate revocation
lookups, push notifications, CDN edges for ordinary downloads, public DNS
resolvers. Left in, these would poison Stage 2: two unrelated actors would
appear to "share infrastructure" because both samples ran on a machine that
phoned Apple's push service, and `fingerprint.match()` would offer that as a
lead. Measured on real VirusTotal captures, this traffic was the large
majority of every host set.

The rule for what belongs here is narrow and deliberate:

    Exclude only infrastructure the operator of the malware CANNOT present as
    their own endpoint.

So Apple push, Canonical's snap store, OCSP/CRL responders and public resolvers
are excluded -- an attacker cannot host C2 on `ocsp.digicert.com`. But shared
hosting an attacker CAN rent or bring a hostname to is deliberately NOT
excluded, even though it generates plenty of noise: AWS/EC2, GCP, Azure,
CloudFront, Cloudflare Workers/Pages, and the dynamic-DNS providers in
`fingerprint._DDNS` are all routinely used for real C2. Dropping those would
discard true positives, which is the worse error of the two.

Nothing here is destructive: `classify()` explains each decision, and callers
keep the excluded set so a UI can show what was filtered and why.
"""
from __future__ import annotations

import ipaddress

# Provider-operated networks. An attacker cannot stand up C2 inside these.
_BENIGN_NETS = (
    # Apple (push, iCloud, software update) -- all of 17/8 is Apple-operated.
    ("17.0.0.0/8", "Apple-operated network"),
    # Canonical: the snap store, seen on every Linux sample we captured.
    ("185.125.188.0/22", "Canonical / Ubuntu snap store"),
    ("91.189.88.0/21", "Canonical / Ubuntu archive"),
    # Fastly and Akamai edge. Customers do not get to pick an edge IP as an
    # endpoint; a malicious Fastly-fronted host appears as its own hostname.
    ("151.101.0.0/16", "Fastly edge"),
    ("199.232.0.0/16", "Fastly edge"),
    ("23.32.0.0/11", "Akamai edge"),
    ("23.192.0.0/11", "Akamai edge"),
    ("2.16.0.0/13", "Akamai edge"),
    ("96.16.0.0/15", "Akamai edge"),
    ("184.24.0.0/13", "Akamai edge"),
    # Google-operated services (NOT GCP customer ranges, which are rentable).
    ("142.250.0.0/15", "Google-operated service"),
    ("172.217.0.0/16", "Google-operated service"),
    ("216.58.192.0/19", "Google-operated service"),
    ("64.233.160.0/19", "Google-operated service"),
)

# Public DNS resolvers: a lookup against one is not a C2 contact.
_RESOLVERS = {
    "1.1.1.1": "Cloudflare public DNS",
    "1.0.0.1": "Cloudflare public DNS",
    "8.8.8.8": "Google public DNS",
    "8.8.4.4": "Google public DNS",
    "9.9.9.9": "Quad9 public DNS",
    "149.112.112.112": "Quad9 public DNS",
    "208.67.222.222": "OpenDNS public DNS",
    "208.67.220.220": "OpenDNS public DNS",
    "64.6.64.6": "Verisign public DNS",
    "76.76.2.0": "ControlD public DNS",
}

# Domains owned and operated by the vendor named. Suffix-matched.
# Deliberately NOT listed: sharepoint.com, onedrive.com, 1drv.ms,
# azurewebsites.net, azureedge.net and blob.core.windows.net. Those are
# customer-controlled or rentable -- anyone can host a payload on a tenant or a
# storage account -- and real campaigns use them. The same reasoning keeps
# Microsoft's Azure IP ranges (52.x and similar) out of _BENIGN_NETS: an
# attacker can rent that space, so excluding it by range would hide live C2.
# The rule throughout is to exclude only infrastructure an attacker cannot
# present as their own endpoint.
_BENIGN_SUFFIXES = {
    # OS and platform telemetry / updates
    "apple.com": "Apple service",
    "icloud.com": "Apple service",
    "mzstatic.com": "Apple service",
    "push.apple.com": "Apple push service",
    "windowsupdate.com": "Windows Update",
    "msftncsi.com": "Windows connectivity check",
    "msftconnecttest.com": "Windows connectivity check",
    "microsoft.com": "Microsoft service",
    "windows.com": "Microsoft service",
    "office.com": "Microsoft service",
    # Microsoft 365 and sign-in telemetry. Matching is exact-suffix, so these
    # never catch the lookalikes the catalogue is full of -- cloud.microsoftshop.org,
    # login-microsoftonline.site, logonmicrosoftonline.com and
    # downloadwindowsupdate.co are all different registrable domains and stay.
    "cloud.microsoft": "Microsoft 365 service",
    "microsoftonline.com": "Microsoft sign-in service",
    "microsoftonline-p.com": "Microsoft sign-in CDN",
    "msauth.net": "Microsoft sign-in service",
    "msauthimages.net": "Microsoft sign-in service",
    "msocdn.com": "Microsoft Office CDN",
    "msedge.net": "Microsoft CDN",
    "office365.com": "Microsoft 365 service",
    "msn.com": "Microsoft news/search service",
    "bing.com": "Microsoft search service",
    "live.com": "Microsoft account service",
    "skype.com": "Microsoft communications service",
    "snapcraft.io": "Canonical snap store",
    "canonical.com": "Canonical service",
    "ubuntu.com": "Ubuntu archive/service",
    "debian.org": "Debian archive",
    "archlinux.org": "Arch archive",
    "mozilla.org": "Mozilla service",
    "mozilla.net": "Mozilla service",
    "mozilla.com": "Mozilla service",
    # Certificate validation: OCSP / CRL / timestamping
    "digicert.com": "certificate validation (OCSP/CRL)",
    "globalsign.com": "certificate validation (OCSP/CRL)",
    "verisign.com": "certificate validation (OCSP/CRL)",
    "sectigo.com": "certificate validation (OCSP/CRL)",
    "comodoca.com": "certificate validation (OCSP/CRL)",
    "letsencrypt.org": "certificate validation (OCSP/CRL)",
    "entrust.net": "certificate validation (OCSP/CRL)",
    "godaddy.com": "certificate validation (OCSP/CRL)",
    "usertrust.com": "certificate validation (OCSP/CRL)",
    "symcb.com": "certificate validation (OCSP/CRL)",
    "symcd.com": "certificate validation (OCSP/CRL)",
    "amazontrust.com": "certificate validation (OCSP/CRL)",
    # Language/package ecosystems a benign installer legitimately fetches
    "python.org": "Python.org distribution",
    "pypi.org": "PyPI package index",
    "pythonhosted.org": "PyPI package files",
    "nodejs.org": "Node.js distribution",
    "npmjs.org": "npm registry",
    "rubygems.org": "RubyGems registry",
    "golang.org": "Go distribution",
    "crates.io": "Rust crates registry",
    # Provider-operated edge infrastructure
    "akamai.net": "Akamai edge",
    "akamaiedge.net": "Akamai edge",
    "akamaitechnologies.com": "Akamai edge",
    "akadns.net": "Akamai edge",
    "edgekey.net": "Akamai edge",
    "edgesuite.net": "Akamai edge",
    "fastly.net": "Fastly edge",
    "fbcdn.net": "Meta CDN",
    "google.com": "Google-operated service",
    "googlevideo.com": "Google-operated service",
    "gvt1.com": "Google-operated service",
    "gvt2.com": "Google-operated service",
    "awswaf.com": "AWS WAF challenge endpoint",
    "gstatic.com": "Google static content",
    "googleapis.com": "Google API service",
    "googleusercontent.com": "Google-operated service",
    "1e100.net": "Google-operated service",
    "root-servers.net": "DNS root server",
    "in-addr.arpa": "reverse-DNS zone",
}

# Hostname prefixes that mark certificate/revocation traffic whatever the
# domain, e.g. ocsp2.globalsign.com, crl3.digicert.com.
_CERT_PREFIXES = ("ocsp", "crl", "pki", "aia")

# Infrastructure that is noisy but attacker-usable, so deliberately kept. Named
# here only to document the decision -- the filter never consults this.
_KEPT_DESPITE_NOISE = (
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net",
    "workers.dev", "pages.dev", "r2.dev", "herokuapp.com", "firebaseapp.com",
    "web.app", "glitch.me", "github.io", "githubusercontent.com",
)


def _host_from(value: str, t: str) -> str:
    """The hostname to judge, for a domain or a URL."""
    v = (value or "").strip().lower()
    if t == "url":
        v = v.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
        v = v.rsplit(":", 1)[0] if v.count(":") == 1 else v
    return v.rstrip(".")


def _suffix_hit(host: str) -> str:
    for suffix, why in _BENIGN_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            return why
    return ""


def classify(value: str, t: str) -> tuple[bool, str]:
    """(is_benign, reason). reason is '' when the indicator is kept.

    Offline and pure: no DNS, no HTTP. Callers may add their own enrichment,
    but the decision here never depends on the network being reachable.
    """
    if t == "ip":
        ip = (value or "").strip()
        if ip in _RESOLVERS:
            return True, _RESOLVERS[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, ""
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True, "private/loopback address"
        for cidr, why in _BENIGN_NETS:
            if addr in ipaddress.ip_network(cidr):
                return True, why
        return False, ""

    if t in ("domain", "url"):
        host = _host_from(value, t)
        if not host:
            return False, ""
        why = _suffix_hit(host)
        if why:
            return True, why
        label = host.split(".", 1)[0]
        if any(label.startswith(p) for p in _CERT_PREFIXES) and label not in ("pkiconnect",):
            return True, "certificate validation (OCSP/CRL)"
        return False, ""

    return False, ""


def split(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Partition indicator rows into (kept, benign). Benign rows gain 'why'."""
    kept, benign = [], []
    for r in rows:
        is_benign, why = classify(r.get("value", ""), r.get("type", ""))
        if is_benign:
            benign.append({**r, "why": why})
        else:
            kept.append(r)
    return kept, benign
