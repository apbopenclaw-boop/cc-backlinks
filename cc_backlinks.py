#!/usr/bin/env python3
"""
Common Crawl Backlink Finder

Finds all domains linking to a target domain using Common Crawl's
Web Data Commons Hyperlink Graph (domain-level). Results are stored
in a local SQLite database for gap analysis and historical tracking.

Security: parameterized DuckDB queries, strict input validation,
no shell interpolation. See README.md for full threat model.
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

import duckdb

DEFAULT_RELEASE = "cc-main-2026-jan-feb-mar"
BASE_URL = "https://data.commoncrawl.org/projects/hyperlinkgraph/{release}/domain"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "cc-backlinks")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "backlinks.db")

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")
RELEASE_RE = re.compile(r"^cc-main-\d{4}-[a-z\-]+$")

PAGERANK_API_URL = "https://openpagerank.com/api/v1.0/getPageRank"
PAGERANK_BATCH_SIZE = 100
PAGERANK_BATCH_DELAY = 5  # seconds between API batches


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain) or len(domain) > 253:
        raise ValueError(f"Invalid domain: {domain!r}")
    return domain


def validate_release(release: str) -> str:
    if not RELEASE_RE.match(release):
        raise ValueError(f"Invalid release format: {release!r}")
    return release


def reverse_domain(domain: str) -> str:
    return ".".join(reversed(domain.split(".")))


# ── SQLite persistence ──────────────────────────────────────────────

def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS crawls (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT NOT NULL,
            release     TEXT NOT NULL,
            crawled_at  TEXT NOT NULL,
            result_count INTEGER NOT NULL,
            UNIQUE(target, release)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS backlinks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            crawl_id        INTEGER NOT NULL REFERENCES crawls(id),
            linking_domain  TEXT NOT NULL,
            num_hosts       INTEGER NOT NULL,
            page_rank       REAL,
            UNIQUE(crawl_id, linking_domain)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS pagerank_cache (
            domain      TEXT PRIMARY KEY,
            page_rank   REAL,
            fetched_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE INDEX IF NOT EXISTS idx_backlinks_domain
        ON backlinks(linking_domain)
    """)
    con.execute("""
        CREATE INDEX IF NOT EXISTS idx_backlinks_crawl
        ON backlinks(crawl_id)
    """)
    con.commit()
    return con


def store_results(target: str, release: str, results: list[dict],
                  db_path: str = DB_PATH) -> int:
    con = init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "DELETE FROM backlinks WHERE crawl_id IN "
        "(SELECT id FROM crawls WHERE target = ? AND release = ?)",
        (target, release),
    )
    con.execute(
        "DELETE FROM crawls WHERE target = ? AND release = ?",
        (target, release),
    )
    cur = con.execute(
        "INSERT INTO crawls (target, release, crawled_at, result_count) VALUES (?, ?, ?, ?)",
        (target, release, now, len(results)),
    )
    crawl_id = cur.lastrowid
    con.executemany(
        "INSERT INTO backlinks (crawl_id, linking_domain, num_hosts) VALUES (?, ?, ?)",
        [(crawl_id, r["domain"], r["num_hosts"]) for r in results],
    )
    con.commit()
    con.close()
    return crawl_id


def get_stored(target: str, release: str = None,
               db_path: str = DB_PATH) -> list[dict] | None:
    """Retrieve stored backlinks. Returns None if not found."""
    if not os.path.exists(db_path):
        return None
    con = init_db(db_path)
    if release:
        row = con.execute(
            "SELECT id FROM crawls WHERE target = ? AND release = ? "
            "ORDER BY crawled_at DESC LIMIT 1",
            (target, release),
        ).fetchone()
    else:
        row = con.execute(
            "SELECT id FROM crawls WHERE target = ? "
            "ORDER BY crawled_at DESC LIMIT 1",
            (target,),
        ).fetchone()
    if not row:
        con.close()
        return None
    results = con.execute(
        "SELECT linking_domain, num_hosts, page_rank FROM backlinks "
        "WHERE crawl_id = ? ORDER BY num_hosts DESC, linking_domain",
        (row[0],),
    ).fetchall()
    con.close()
    return [{"domain": r[0], "num_hosts": r[1], "page_rank": r[2]} for r in results]


def list_crawls(db_path: str = DB_PATH) -> list[dict]:
    """List all stored crawls."""
    if not os.path.exists(db_path):
        return []
    con = init_db(db_path)
    rows = con.execute(
        "SELECT id, target, release, crawled_at, result_count "
        "FROM crawls ORDER BY crawled_at DESC"
    ).fetchall()
    con.close()
    return [{"id": r[0], "target": r[1], "release": r[2],
             "crawled_at": r[3], "count": r[4]} for r in rows]


def gap_analysis(target: str, competitor: str, release: str = None,
                 db_path: str = DB_PATH) -> list[dict]:
    """Find domains linking to competitor but NOT to target."""
    own = get_stored(target, release, db_path)
    comp = get_stored(competitor, release, db_path)
    if own is None or comp is None:
        missing = []
        if own is None:
            missing.append(target)
        if comp is None:
            missing.append(competitor)
        raise ValueError(f"No stored data for: {', '.join(missing)}. Run crawl first.")
    own_domains = {r["domain"] for r in own}
    gaps = [r for r in comp if r["domain"] not in own_domains]
    return sorted(gaps, key=lambda r: r["num_hosts"], reverse=True)


# ── PageRank enrichment ────────────────────────────────────────────

def fetch_pagerank(domains: list[str], api_key: str,
                   batch_delay: float = PAGERANK_BATCH_DELAY) -> dict[str, float]:
    """Fetch Open PageRank scores for a list of domains.
    Returns {domain: page_rank} mapping.
    API: https://www.domcop.com/openpagerank/documentation
    """
    scores = {}
    batches = [domains[i:i + PAGERANK_BATCH_SIZE]
               for i in range(0, len(domains), PAGERANK_BATCH_SIZE)]

    for batch_num, batch in enumerate(batches, 1):
        params = "&".join(f"domains[]={d}" for d in batch)
        url = f"{PAGERANK_API_URL}?{params}"

        req = urllib.request.Request(url)
        req.add_header("API-OPR", api_key)

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            print(f">> PageRank batch {batch_num}/{len(batches)} failed: {e}",
                  file=sys.stderr)
            continue

        for item in data.get("response", []):
            domain = item.get("domain", "")
            pr = item.get("page_rank_decimal")
            if pr is not None:
                scores[domain] = float(pr)

        print(f">> PageRank batch {batch_num}/{len(batches)}: "
              f"{len(data.get('response', []))} domains scored", file=sys.stderr)

        if batch_num < len(batches):
            time.sleep(batch_delay)

    return scores


def enrich_pagerank(api_key: str, db_path: str = DB_PATH,
                    batch_delay: float = PAGERANK_BATCH_DELAY) -> int:
    """Enrich all stored backlink domains with PageRank scores.
    Uses a cache table to avoid re-fetching known domains.
    Returns count of newly scored domains.
    """
    con = init_db(db_path)

    # Find all unique domains not yet in cache
    rows = con.execute("""
        SELECT DISTINCT linking_domain FROM backlinks
        WHERE linking_domain NOT IN (SELECT domain FROM pagerank_cache)
    """).fetchall()
    domains = [r[0] for r in rows]

    if not domains:
        print(">> All domains already have PageRank scores cached.", file=sys.stderr)
        con.close()
        return 0

    print(f">> Fetching PageRank for {len(domains)} uncached domains...", file=sys.stderr)
    scores = fetch_pagerank(domains, api_key, batch_delay)

    # Store in cache
    now = datetime.now(timezone.utc).isoformat()
    con.executemany(
        "INSERT OR REPLACE INTO pagerank_cache (domain, page_rank, fetched_at) VALUES (?, ?, ?)",
        [(d, s, now) for d, s in scores.items()],
    )

    # Update backlinks table from cache
    con.execute("""
        UPDATE backlinks SET page_rank = (
            SELECT page_rank FROM pagerank_cache WHERE pagerank_cache.domain = backlinks.linking_domain
        ) WHERE linking_domain IN (SELECT domain FROM pagerank_cache)
    """)

    con.commit()
    con.close()
    print(f">> Enriched {len(scores)} domains with PageRank scores.", file=sys.stderr)
    return len(scores)


# ── Download & Query ───────────────────────────────────────────────

def download(url: str, dest: str) -> None:
    if os.path.exists(dest):
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print(f">> downloading {os.path.basename(dest)} ...", file=sys.stderr)
    print(f"   from {url}", file=sys.stderr)
    urllib.request.urlretrieve(url, dest)


def query_backlinks(domain: str, release: str = DEFAULT_RELEASE) -> list[dict]:
    domain = validate_domain(domain)
    release = validate_release(release)
    rev_domain = reverse_domain(domain)

    cache = os.path.join(CACHE_DIR, release)
    vertices = os.path.join(cache, f"{release}-domain-vertices.txt.gz")
    edges = os.path.join(cache, f"{release}-domain-edges.txt.gz")

    base = BASE_URL.format(release=release)
    download(f"{base}/{release}-domain-vertices.txt.gz", vertices)
    download(f"{base}/{release}-domain-edges.txt.gz", edges)

    print(f">> querying backlinks to {domain} ...", file=sys.stderr)
    print(f">> first run scans ~16 GB of gzipped edges; expect several minutes", file=sys.stderr)

    con = duckdb.connect(":memory:")
    results = con.execute("""
        WITH vertices AS (
            SELECT * FROM read_csv($1, delim='\t', header=false,
                columns={'id':'BIGINT','rev_domain':'VARCHAR','num_hosts':'BIGINT'})
        ),
        target AS (
            SELECT id FROM vertices WHERE rev_domain = $3
        ),
        inbound AS (
            SELECT from_id FROM read_csv($2, delim='\t', header=false,
                columns={'from_id':'BIGINT','to_id':'BIGINT'})
            WHERE to_id = (SELECT id FROM target)
        )
        SELECT
            array_to_string(list_reverse(string_split(v.rev_domain, '.')), '.') AS linking_domain,
            v.num_hosts
        FROM inbound i
        JOIN vertices v ON v.id = i.from_id
        ORDER BY v.num_hosts DESC, linking_domain
    """, [vertices, edges, rev_domain]).fetchall()
    con.close()

    return [{"domain": row[0], "num_hosts": row[1]} for row in results]


def crawl_and_store(domain: str, release: str = DEFAULT_RELEASE,
                    db_path: str = DB_PATH) -> tuple[list[dict], int]:
    """Query backlinks and persist to SQLite. Returns (results, crawl_id)."""
    results = query_backlinks(domain, release)
    crawl_id = store_results(domain, release, results, db_path)
    print(f">> stored {len(results)} backlinks in {db_path} (crawl #{crawl_id})", file=sys.stderr)
    return results, crawl_id


def main():
    parser = argparse.ArgumentParser(description="Find backlinks via Common Crawl Hyperlink Graph")
    parser.add_argument("--db", default=DB_PATH, help="SQLite DB path")

    out_args = argparse.ArgumentParser(add_help=False)
    out_args.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    out_args.add_argument("--csv", action="store_true", dest="as_csv", help="Output as CSV")
    out_args.add_argument("-o", "--output", help="Output file (default: stdout)")

    sub = parser.add_subparsers(dest="cmd")
    crawl_parser = sub.add_parser("crawl", parents=[out_args], help="Crawl backlinks for a domain")
    crawl_parser.add_argument("domain", help="Target domain (e.g. example.com)")
    crawl_parser.add_argument("--release", default=DEFAULT_RELEASE, help=f"CC release (default: {DEFAULT_RELEASE})")
    crawl_parser.add_argument("--no-store", action="store_true", help="Skip SQLite storage")
    sub.add_parser("list", help="List stored crawls")
    stored_parser = sub.add_parser("stored", parents=[out_args], help="Show stored backlinks for a domain")
    stored_parser.add_argument("domain", help="Target domain")
    gap_parser = sub.add_parser("gap", parents=[out_args], help="Gap analysis: competitor backlinks you don't have")
    gap_parser.add_argument("domain", help="Your domain")
    gap_parser.add_argument("competitor", help="Competitor domain")
    enrich_parser = sub.add_parser("enrich", help="Enrich stored domains with Open PageRank scores")
    enrich_parser.add_argument("--api-key", default=os.environ.get("OPENPAGERANK_API_KEY", ""),
                               help="Open PageRank API key (or set OPENPAGERANK_API_KEY env var)")
    enrich_parser.add_argument("--delay", type=float, default=PAGERANK_BATCH_DELAY,
                               help=f"Seconds between API batches (default: {PAGERANK_BATCH_DELAY})")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return

    if args.cmd == "list":
        crawls = list_crawls(args.db)
        if not crawls:
            print("No crawls stored yet.")
        for c in crawls:
            print(f"#{c['id']:>3}  {c['target']:<40} {c['release']}  "
                  f"{c['count']:>5} links  {c['crawled_at']}")
        return

    if args.cmd == "enrich":
        if not args.api_key:
            print("Error: --api-key required or set OPENPAGERANK_API_KEY env var",
                  file=sys.stderr)
            sys.exit(1)
        count = enrich_pagerank(args.api_key, args.db, args.delay)
        print(f"Done. {count} domains enriched with PageRank scores.")
        return

    if args.cmd == "stored":
        results = get_stored(args.domain, db_path=args.db)
        if results is None:
            print(f"No stored data for {args.domain}. Run a crawl first.")
            return
    elif args.cmd == "gap":
        results = gap_analysis(args.domain, args.competitor, db_path=args.db)
        if not results:
            print("No gap found — you have all their backlinks!")
            return
    else:
        results = query_backlinks(args.domain, args.release)
        if not args.no_store:
            store_results(args.domain, args.release, results, args.db)
            print(f">> stored {len(results)} backlinks in {args.db}", file=sys.stderr)

    out = open(args.output, "w") if args.output else sys.stdout

    if args.as_json:
        json.dump(results, out, indent=2)
        out.write("\n")
    elif args.as_csv:
        fieldnames = ["domain", "num_hosts"]
        if any(r.get("page_rank") is not None for r in results):
            fieldnames.append("page_rank")
        writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    else:
        if not results:
            print("No backlinks found.")
        else:
            has_pr = any(r.get("page_rank") is not None for r in results)
            if has_pr:
                print(f"{'Linking Domain':<50} {'Hosts':>8} {'PageRank':>10}")
                print("-" * 70)
                for r in results:
                    pr = f"{r['page_rank']:.1f}" if r.get("page_rank") is not None else "-"
                    print(f"{r['domain']:<50} {r['num_hosts']:>8} {pr:>10}")
            else:
                print(f"{'Linking Domain':<60} {'Hosts':>10}")
                print("-" * 72)
                for r in results:
                    print(f"{r['domain']:<60} {r['num_hosts']:>10}")
            print(f"\nTotal: {len(results)} linking domains")

    if args.output:
        out.close()
        print(f">> wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
