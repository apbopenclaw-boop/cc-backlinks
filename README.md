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

# Output as JSON or CSV
python cc_backlinks.py crawl example.com --json
python cc_backlinks.py gap mysite.com competitor.com --csv -o gaps.csv

# Use a specific Common Crawl release
python cc_backlinks.py crawl example.com --release cc-main-2025-oct-nov-dec
```

## Python API

```python
from cc_backlinks import crawl_and_store, get_stored, gap_analysis, list_crawls, enrich_pagerank

# Crawl + store
results, crawl_id = crawl_and_store("example.com")

# Retrieve from SQLite (no network)
results = get_stored("example.com")

# Gap analysis
gaps = gap_analysis("mysite.com", "competitor.com")

# Enrich all stored domains with PageRank
count = enrich_pagerank(api_key="your_key_here")

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
crawls(id, target, release, crawled_at, result_count)       -- UNIQUE(target, release)
backlinks(id, crawl_id, linking_domain, num_hosts, page_rank) -- UNIQUE(crawl_id, linking_domain)
pagerank_cache(domain, page_rank, fetched_at)                -- PRIMARY KEY(domain)
```

The `pagerank_cache` table avoids re-fetching scores for domains already looked up. The `enrich` command only queries uncached domains.

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
4. **Enrich with PageRank:** `python cc_backlinks.py enrich --api-key YOUR_KEY`
5. **Prioritize:** Sort by `page_rank` and `num_hosts`, filter for industry relevance
6. **Outreach:** Target high-authority gap domains for link-building

Get a free Open PageRank API key at https://www.domcop.com/openpagerank/

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

## Dependencies

- Python 3.10+
- [DuckDB](https://duckdb.org/) (`pip install duckdb`)
- [Open PageRank API key](https://www.domcop.com/openpagerank/) (free, optional — for `enrich` command)

## License

MIT
