from darkfeeds.deepweb import build_deepweb_signal
from darkfeeds.news import parse_rss_feed


def test_parse_rss_feed_extracts_story_fields():
    xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>Threat News</title>
        <item>
          <title>APT36 activity reported against telecom targets</title>
          <link>https://example.com/apt36</link>
          <guid>abc-123</guid>
          <pubDate>Tue, 01 Oct 2024 10:00:00 +0000</pubDate>
          <description>Researchers linked the campaign to CVE-2024-5678 and credential theft.</description>
        </item>
      </channel>
    </rss>
    '''

    items = parse_rss_feed(xml, source_name="Threat News")

    assert len(items) == 1
    assert items[0]["title"] == "APT36 activity reported against telecom targets"
    assert items[0]["link"] == "https://example.com/apt36"
    assert "CVE-2024-5678" in items[0]["description"]


def test_build_deepweb_signal_extracts_threat_actor_and_cve():
    text = "APT36 exploited CVE-2024-5678 in telecom infrastructure using CrimsonRAT."

    signal = build_deepweb_signal(text, source_name="Dread")

    assert signal.threat_actor == "APT36 (Transparent Tribe)"
    assert signal.cve_ids == ["CVE-2024-5678"]
    assert signal.malware_family.lower() == "crimsonrat"
    assert signal.target_country == ""
