# Changelog

All notable changes to GroundTrace are recorded here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Home page at `/`; the dashboard moves to `/dashboard`. Old `/#CVE-...` links redirect.
- Dashboard overview screen and `GET /overview`: totals, hosting map, measured
  precision, indicator types, active families, collection runs and feed kinds.
- Watchlist screen, and Threat Graph as its own navigation entry.
- Collapsible, grouped navigation.
- Malware Families list (`GET /malware`) and family pages: type, activity, observed reach,
  linked groups and capabilities, each with its source. Empty sections are hidden.
- Family descriptions, aliases, attribution and reports from Malpedia and MISP Galaxy, downloaded
  to the local data directory. `GROUNDTRACE_MALPEDIA=0` leaves out Malpedia (CC BY-NC-SA 3.0).

### Changed
- Renamed the project to GroundTrace. Environment variables, the data directory (`~/.groundtrace`),
  the Docker user and the Docker volume (`groundtrace-data`) all change. STIX export IDs change too.
- New visual design across the dashboard. Existing views keep their behaviour.
- "Alerts delivered" is now "Alerts raised", and the Alerts view says plainly when
  no delivery channel is configured.

### Fixed
- Emerging Radar showed `EPSS: NaN%` and zero PoCs and signals on every row: it
  read fields the radar does not return.
- The watcher reported `ok` however old its last cycle was, and despite step errors.
- The CVE list described its display limit as "CVEs matching filter criteria".
- Input placeholders failed text contrast.
- Family pages undercounted ThreatFox file hashes and URLs.
- "Akira Stealer" was attributed to the Akira group because of its name.

## [0.2.0] — 2026-11-02

The release that makes the tool's central claim checkable. Footprint matching
now reports a measured precision, abstains when the evidence is thin, and ships
the harness that produced the number.

### Added
- **Measured attribution accuracy.** `scripts/validate_footprints.py` runs
  leave-one-out over the indicator catalogue and prints precision, wrong-group
  rate and abstention for every threshold. The catalogue is split by a hash of
  the group key so thresholds are tuned on one half and quoted from the other,
  and tests are capped per group so one bulk feed cannot set the headline.
  Running it with no arguments reproduces the figures in README.md. It exits
  non-zero if strict precision falls below 0.60.
- **Two operating points on `fingerprint.match()`**: `strict` (two independent
  habits must agree; 72.2% top-1 precision, 2.0% wrong-group) and `broad` (one
  rare habit, labelled a lead; 69.5%). Both measured on held-out groups.
  `GET /infra/match` takes `?mode=`.
- **Reliability on every result.** Matches carry `reliability`,
  `reliability_basis` and `verdict: "lead"`. The dashboard shows the measured
  figure with its method, and an abstention card explaining what was checked
  when nothing reaches the threshold.
- **Footprint freshness.** Footprints are classified fresh / aging / historical
  / undated. A historical footprint caps reliability at 0.45, labelled a
  judgement rather than a measurement.
- **`groundtrace/claims.py`** — an append-only ledger of every claim: the evidence,
  the measured reliability, and what would prove it wrong. Corrections insert a
  new row and supersede the old one; immutability is enforced by SQLite
  triggers. `GET /claims?q=&history=`.
- **Corroboration status on verification.** Every verdict reports `sources` and
  `corroborated`.
- URLhaus payload lookups for md5/sha256 hashes.
- Explainable risk score: every CVE shows each input, the rule applied (EPSS, KEV
  floor or default) and a link to its source, and the inputs multiply out to the score.
- PoC finder (`GET /pocs/<CVE>` and a dashboard button): public exploit links from
  PoC-in-GitHub, GitHub search and NVD references, ranked with malware-lure red
  flags. Links only; nothing is downloaded or executed.
- Keyword search with NVD pull (`POST /search/nvd`): newest matching CVEs fetched
  and scored in one step (bulk EPSS lookup).
- Watchlists (`/watchlist`): the watcher alerts on new CVEs matching saved keywords;
  adding a keyword marks its existing matches as seen, so there is no alert flood.

### Changed
- **Token rarity weighting.** Domain tokens are weighted by inverse document
  frequency instead of counting equally, and the four-token cap now keeps the
  informative tokens rather than the first four alphabetically.
- **`_tokens()` strips the public suffix.** Tokenising the whole domain had made
  `com` the most widespread "habit" in the catalogue, present in 86% of groups
  and worth a full point. The TLD signal was also demoted from 0.3 to 0.1.
  Together these cut the wrong-group rate from 46.5% to 2.0%.
- **"Confirmed" now requires two independent sources.** Verification previously
  returned "confirmed" from a single feed. VirusTotal counts once, at 10+
  detections, however many engines it aggregates; a single source is reported
  as a lead naming that source.
- **The radar makes no prediction.** The hot/warming bands at 60 and 40 were
  never fitted against historical outcomes and are removed; entries are
  "ranked" or "insufficient". Watcher alerts now fire on checkable facts — a
  PoC predating NVD publication, EPSS at or above 0.9 while absent from KEV, or
  a 7-day EPSS rise of at least 0.05 — instead of a score threshold that was
  unreachable and had never produced an alert.
- Radar components report whether they could be measured at all; points are
  summed only over what was measurable, and entries carry `points_available`,
  `coverage` and `unmeasured`.
- `Scores.asset_criticality` is rejected outside 0–1 at construction, `risk` is
  clamped to 0–100, and `--criticality` is validated as a usage error.
- TLS verification uses certifi's root bundle when available, so services
  signed by CAs absent from the local store resolve instead of failing.
- Local search matches the CVE id, title, description and affected products, and
  requires every word, instead of matching anywhere in the stored record (which
  hit reference URLs and boilerplate).

### Removed
- **Pseudo-confidence.** Match results previously carried a confidence derived
  from `score / (score + 3)`, which read as authoritative while measuring
  nothing.

### Fixed
- **A failed lookup is no longer reported as an absent result.** `poc.indexed_repos()`
  returned `[]` on any failure, so a rate-limited index lookup was recorded as
  evidence that no public PoC existed — zeroing that radar component on every
  entry ever computed. `threatfox()` and `urlhaus()` had the same defect and
  reported transport failures as "not found".
- Dead modular-dashboard files removed (`static/js/app.js`, `pages/`,
  `components/`, and the unused stylesheets).

## [0.1.0] — 2026-10-26

First public release.

### Vulnerability intelligence
- Live CVE analysis from NVD 2.0, CISA KEV and FIRST EPSS, with offline demo data.
- Risk score = CVSS × exploit likelihood × asset criticality, where a CISA KEV listing
  floors exploit likelihood at 0.9 — observed exploitation outweighs a low EPSS forecast.
- Provenance classifiers: how a flaw was discovered and on what basis it went public,
  each label backed by the phrase or URL that justified it; flags flaws public before a
  patch existed.
- Five-part analysis per CVE: what it is, root cause (CWE-driven), how it was found,
  business impact, security principle violated.
- Clear distinction between "NVD unreachable", "no such published CVE" and "reserved in
  the CVE.org registry", with a web-search fallback for CVEs not yet in NVD.

### Threat intelligence
- Collectors for MalwareBazaar, ThreatFox, AlienVault OTX, RansomLook and security news
  RSS; IOC and CVE extraction; IP enrichment (RDAP, Team Cymru, optional Shodan) and
  hash reputation (optional VirusTotal).
- CVE ↔ underground-signal correlation on every CVE record.
- Threat map: per-country infrastructure profiles (threat types, malware families,
  hosting providers, cloud vs consumer-ISP share, actors) and auto-written findings;
  actor-origin layer from curated attribution.

### Platform
- REST API and analyst dashboard (stdlib `http.server`), localhost-only unless an API
  key is set; strict CSP, no external assets.
- Scheduled watcher with deduplicated alerts to Slack, Discord, Telegram or any
  webhook; first run is a silent baseline.
- SQLite stores with run and score history (WAL, safe for API + watcher together).
- Docker image (non-root, health check) and docker-compose for API + watcher.
- Offline test suite and CI (lint, byte-compile, tests on Python 3.12/3.13, Docker build).

### Notes
- ransomware.live replaced by RansomLook after its free API was retired.
- The Tor crawler is experimental and opt-in.
