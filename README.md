# cc-backlinks — Common Crawl Backlink Finder

Find every domain linking to any website using [Common Crawl's Hyperlink Graph](https://webdatacommons.org/hyperlinkgraph/). No API keys, no rate limits — just open data.

Built for SEO backlink audits, competitor gap analysis, and link-building research.

## Quick Start

```bash
pip install duckdb
python cc_backlinks.py crawl example.com
```

First run downloads ~18 GB of Common Crawl data (cached for subsequent queries).

## Commands

```bash
# Crawl backlinks for a domain (auto-stores in SQLite)
python cc_backlinks.py crawl example.com

# List all stored crawls
python cc_backlinks.py list

# View stored results (no network needed)
python cc_backlinks.py stored example.com

# Gap analysis: domains linking to competitor but NOT to you
python cc_backlinks.py gap mysite.com competitor.com

# Enrich stored domains with Open PageRank scores
export OPENPAGERANK_API_KEY=your_key_here
python cc_backlinks.py enrich
# Or pass key directly:
python cc_backlinks.py enrich --api-key your_key_here

# Enrich with Majestic Million (free, no key needed — downloads ~80 MB CSV)
python cc_backlinks.py enrich-majestic

# Enrich with Tranco top-1M ranking (free, no key needed)
python cc_backlinks.py enrich-tranco

# Output as JSON or CSV
python cc_backlinks.py crawl example.com --json
python cc_backlinks.py gap mysite.com competitor.com --csv -o gaps.csv

# Use a specific Common Crawl release
python cc_backlinks.py crawl example.com --release cc-main-2025-oct-nov-dec
```

## Python API

```python
from cc_backlinks import (crawl_and_store, get_stored, gap_analysis, list_crawls,
                          enrich_pagerank, enrich_majestic, enrich_tranco)

# Crawl + store
results, crawl_id = crawl_and_store("example.com")

# Retrieve from SQLite (no network)
results = get_stored("example.com")

# Gap analysis
gaps = gap_analysis("mysite.com", "competitor.com")

# Enrich with multiple authority sources
count = enrich_pagerank(api_key="your_key_here")  # Open PageRank (needs API key)
count = enrich_majestic()                          # Majestic Million (free)
count = enrich_tranco()                            # Tranco top-1M (free)

# List crawls
crawls = list_crawls()
```

## How It Works

```
Common Crawl S3
  ├── domain-vertices.txt.gz  (~2 GB)   ← every domain + ID + host count
  └── domain-edges.txt.gz     (~16 GB)  ← every domain→domain link
        │
        ▼
  ~/.cache/cc-backlinks/<release>/       ← downloaded once, cached locally
        │
        ▼
  DuckDB in-memory query                ← parameterized, no SQL injection
        │
        ▼
  data/backlinks.db (SQLite)             ← persistent storage
        │
        ▼
  Table / JSON / CSV output
```

## Storage

### SQLite Database (`data/backlinks.db`)

```sql
crawls(id, target, release, crawled_at, result_count)                    -- UNIQUE(target, release)
backlinks(id, crawl_id, linking_domain, num_hosts, page_rank)            -- UNIQUE(crawl_id, linking_domain)
pagerank_cache(domain, page_rank, fetched_at)                            -- PRIMARY KEY(domain)
majestic_cache(domain, global_rank, tld_rank, ref_subnets, ref_ips, fetched_at) -- PRIMARY KEY(domain)
tranco_cache(domain, tranco_rank, fetched_at)                            -- PRIMARY KEY(domain)
```

Cache tables avoid redundant re-downloads. Each enrichment source matches only against domains already in your backlinks table.

Re-crawling the same domain+release replaces previous results.

### Common Crawl Cache (`~/.cache/cc-backlinks/`)

| File | Size |
|------|------|
| `domain-vertices.txt.gz` | ~2 GB |
| `domain-edges.txt.gz` | ~16 GB |

Shared across all queries using the same release. Delete to free space:
```bash
rm -rf ~/.cache/cc-backlinks/<release>/
```

## SEO Workflow

1. **Crawl your site:** `python cc_backlinks.py crawl mysite.com`
2. **Crawl competitors:** `python cc_backlinks.py crawl competitor1.com`
3. **Find gaps:** `python cc_backlinks.py gap mysite.com competitor1.com --csv -o gaps.csv`
4. **Enrich with authority data:**
   ```bash
   python cc_backlinks.py enrich-majestic   # free, no key
   python cc_backlinks.py enrich-tranco     # free, no key
   python cc_backlinks.py enrich --api-key YOUR_KEY  # optional
   ```
5. **Prioritize:** Sort by authority metrics, filter for industry relevance
6. **Outreach:** Target high-authority gap domains for link-building

## Enrichment Sources

| Source | Command | Data | Cost |
|--------|---------|------|------|
| [Majestic Million](https://majestic.com/reports/majestic-million) | `enrich-majestic` | Global rank, Trust Flow subnets, referring IPs | Free, ~80 MB download |
| [Tranco List](https://tranco-list.eu/) | `enrich-tranco` | Aggregated top-1M rank (Majestic + Chrome UX + Cloudflare Radar) | Free, ~7 MB download |
| [Open PageRank](https://www.domcop.com/openpagerank/) | `enrich` | PageRank score (0–10) | Free API key required |

## Data Freshness

Common Crawl publishes hyperlink graphs quarterly. Check available releases:
https://data.commoncrawl.org/projects/hyperlinkgraph/

Update `DEFAULT_RELEASE` in `cc_backlinks.py` when new graphs are published.

## Security

This tool was hardened from [retlehs/cf0ac6c74476e766fba2f14076fff501](https://gist.github.com/retlehs/cf0ac6c74476e766fba2f14076fff501).

| Threat | Mitigation |
|--------|-----------|
| SQL injection via domain input | Parameterized queries (`$1`, `$2`, `$3`) |
| SQL injection via heredoc | Eliminated — pure Python/DuckDB API |
| Path traversal via release | Strict regex: `^cc-main-\d{4}-[a-z\-]+$` |
| Arbitrary domain input | Regex whitelist + 253 char limit |
| DuckDB file read/write | No user-controlled SQL |
| Download source | Hardcoded `data.commoncrawl.org` (HTTPS) |
| Majestic download | HTTPS + CSV header validation |
| Tranco download | HTTPS + zip integrity check + size validation |

## Dependencies

- Python 3.10+
- [DuckDB](https://duckdb.org/) (`pip install duckdb`)
- [Open PageRank API key](https://www.domcop.com/openpagerank/) (free, optional — for `enrich` command)
- Internet connection for `enrich-majestic` (~80 MB) and `enrich-tranco` (~7 MB) — no API keys needed

## License

MIT
