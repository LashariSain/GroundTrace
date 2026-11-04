"""The DuckDuckGo fallback parses results and keeps only safe http(s) links,
decoding DDG's /l/?uddg= redirect wrapper. Exercised offline with sample HTML."""
import io

from groundtrace import websearch

_SAMPLE = """
<div class="result results_links">
  <h2 class="result__title">
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwatchtowr.com%2Ffaq&amp;rut=abc">PHP RCE FAQ: CVE-2026-109618</a>
  </h2>
  <a class="result__snippet" href="//x">Reported remote code execution in PHP.</a>
</div>
<div class="result results_links">
  <h2 class="result__title">
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fsansec.io%2Fresearch&amp;rut=def">Critical PHP RCE | Sansec</a>
  </h2>
  <a class="result__snippet" href="//y">Two critical vulnerabilities.</a>
</div>
<div class="result">
  <a class="result__a" href="ftp://not-http/evil">Should be dropped (not http)</a>
</div>
"""


def test_decode_ddg_redirect():
    href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fwatchtowr.com%2Ffaq&rut=abc"
    assert websearch._decode_ddg(href) == "https://watchtowr.com/faq"


def test_parser_extracts_title_url_snippet():
    p = websearch._ResultParser()
    p.feed(_SAMPLE)
    assert p.results[0]["url"] == "https://watchtowr.com/faq"
    assert "CVE-2026-109618" in p.results[0]["title"]
    assert "remote code execution" in p.results[0]["snippet"].lower()


def test_search_web_filters_non_http(monkeypatch):
    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(websearch.urllib.request, "urlopen",
                        lambda *a, **k: _Resp(_SAMPLE.encode("utf-8")))
    out = websearch.search_web("CVE-2026-109618")
    urls = [r["url"] for r in out]
    assert "https://watchtowr.com/faq" in urls
    assert "https://sansec.io/research" in urls
    assert all(u.startswith("https://") for u in urls)  # ftp result dropped


def test_search_web_empty_on_network_error(monkeypatch):
    def boom(*a, **k):
        raise websearch.urllib.error.URLError("down")
    monkeypatch.setattr(websearch.urllib.request, "urlopen", boom)
    assert websearch.search_web("CVE-2026-109618") == []
