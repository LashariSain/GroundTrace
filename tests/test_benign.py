"""Benign-infrastructure filter for sandbox captures. Pure, no network."""
from groundtrace import anyrun, benign


def test_provider_operated_ips_are_benign():
    assert benign.classify("17.253.27.131", "ip")[0]          # Apple
    assert benign.classify("151.101.64.223", "ip")[0]         # Fastly edge
    assert benign.classify("185.125.188.54", "ip")[0]         # Canonical snap
    assert benign.classify("23.54.40.238", "ip")[0]           # Akamai
    assert benign.classify("1.1.1.1", "ip")[0]                # public resolver
    assert benign.classify("192.168.1.10", "ip")[0]           # private
    assert "Apple" in benign.classify("17.57.144.104", "ip")[1]


def test_attacker_usable_hosting_is_kept():
    """The whole point: noisy but rentable infrastructure must survive, because
    real C2 lives there. Dropping it would discard true positives."""
    for ip in ("100.28.198.221", "34.224.193.26"):            # EC2
        assert benign.classify(ip, "ip") == (False, "")
    assert benign.classify("5.230.252.84", "ip") == (False, "")
    for dom in ("evil.cloudfront.net", "c2.workers.dev", "x.herokuapp.com",
                "office-server365.ddns.net", "bad.azurewebsites.net"):
        assert benign.classify(dom, "domain") == (False, "")


def test_vendor_domains_and_cert_traffic_are_benign():
    assert benign.classify("api.snapcraft.io", "domain")[0]
    assert benign.classify("images.apple.com", "domain")[0]
    assert benign.classify("www.python.org", "domain")[0]
    assert benign.classify("ocsp2.globalsign.com", "domain")[0]
    assert benign.classify("crl3.digicert.com", "domain")[0]
    # seen live in Hybrid Analysis captures: Google service endpoints
    for d in ("accounts.google.com", "mtalk.google.com", "clients1.google.com",
              "android.clients.google.com"):
        assert benign.classify(d, "domain")[0], d
    assert "OCSP" in benign.classify("ocsp.anything-else.test", "domain")[1]
    # a lookalike must not match by substring
    assert benign.classify("apple.com.evil.ru", "domain") == (False, "")
    assert benign.classify("notapple.com", "domain") == (False, "")


def test_urls_are_judged_by_host():
    assert benign.classify("http://ocsp2.globalsign.com/rootr3/MFIwUDBO", "url")[0]
    assert benign.classify("https://www.python.org/ftp/python/3.12.3/x.exe", "url")[0]
    assert benign.classify("http://update-sync.ddns.net/gate.php", "url") == (False, "")
    assert benign.classify("http://user@images.apple.com:8080/x", "url")[0]


def test_to_rows_filters_and_records_what_it_dropped():
    cap = {"hash": "a" * 64, "family": "trojan.test", "detonated_at": "2026-10-30",
           "c2": [
               {"value": "17.253.27.131", "type": "ip"},        # Apple -> drop
               {"value": "api.snapcraft.io", "type": "domain"},  # Canonical -> drop
               {"value": "1.1.1.1", "type": "ip"},               # resolver -> drop
               {"value": "5.230.252.84", "type": "ip"},          # keep
               {"value": "office-portal.servehttp.com", "type": "domain"},  # keep
           ]}
    rows = anyrun.to_rows(cap)
    assert {r["value"] for r in rows} == {"5.230.252.84", "office-portal.servehttp.com"}
    assert all(r["kind"] == "sandbox" and r["first_seen"] == "2026-10-30" for r in rows)
    # dropped rows are retained on the capture, with a reason, not lost
    assert len(cap["benign"]) == 3
    assert all(b["why"] for b in cap["benign"])
    # and the filter can be switched off
    assert len(anyrun.to_rows(dict(cap), keep_benign=True)) == 5


def test_split_is_a_partition():
    rows = [{"value": "8.8.8.8", "type": "ip"}, {"value": "9.9.9.9", "type": "ip"},
            {"value": "1.2.3.4", "type": "ip"}, {"value": "junk", "type": "ip"}]
    kept, dropped = benign.split(rows)
    assert len(kept) + len(dropped) == len(rows)
    assert {r["value"] for r in kept} == {"1.2.3.4", "junk"}   # unparseable -> kept


def test_microsoft_365_telemetry_is_filtered():
    """Real Microsoft-operated endpoints a sample contacts on its own."""
    for host, why in (
        ("m365.cloud.microsoft", "Microsoft 365"),
        ("atm.teams.mira.tm.svc.cloud.microsoft", "Microsoft 365"),
        ("login.microsoftonline.com", "sign-in"),
        ("api.msn.com", "news/search"),
        ("assets.msn.com", "news/search"),
    ):
        is_benign, reason = benign.classify(host, "domain")
        assert is_benign, host
        assert why in reason, (host, reason)


def test_microsoft_lookalikes_are_never_filtered():
    """The dangerous half of the same change.

    The catalogue is full of phishing and malware domains built to read like
    Microsoft. Matching is exact-suffix for this reason: a substring rule would
    delete live C2 and phishing infrastructure. Every host here is a different
    registrable domain and must survive.
    """
    for host in ("cloud.microsoftshop.org", "login-microsoftonline.site",
                 "logonmicrosoftonline.com", "microsoftonline.agency",
                 "downloadwindowsupdate.co", "auspost-parcel-office.com",
                 "office-server365.ddns.net", "microsoft-flash.com",
                 "2-sa-sharepoint.com"):
        assert benign.classify(host, "domain") == (False, ""), host


def test_customer_controlled_microsoft_surfaces_are_kept():
    """Tenant and storage surfaces are rentable, so they stay.

    Anyone can host a payload on a SharePoint tenant, a OneDrive link or an
    Azure storage account, and campaigns do. Excluding them would hide real
    delivery infrastructure, which is the opposite of what this filter is for.
    """
    for host in ("contoso.sharepoint.com", "evil.blob.core.windows.net",
                 "payload.azurewebsites.net", "cdn.azureedge.net"):
        assert benign.classify(host, "domain") == (False, ""), host


def test_azure_ip_space_is_kept():
    """Azure address space is rentable, so it is not range-filtered."""
    for ip in ("52.123.250.10", "13.107.42.14", "20.112.52.29"):
        assert benign.classify(ip, "ip") == (False, ""), ip
