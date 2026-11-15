# symbolicator-server

A Python stand-in for ipswd's symbol server. It scans IPSWs into a SQLite
database and serves the same `/v1/...` API, so `ipsw symbolicate --server`
works against it.


## How it differs from ipswd

The API and the answers are the same: a lookup returns the same symbol ipswd
would, including which one wins when several cover an address (the first one
inserted). What changes is how symbols are stored and how scans are fed in.

**Symbol storage**

| | ipswd | symbolicator-server |
|---|---|---|
| Rows per symbol | 2: `symbols (id, name_id, start, end)` plus `macho_syms (macho_uuid, symbol_id)` | 1: `symbols (macho_id, off, seq, size, name_code)`, `WITHOUT ROWID` |
| Mach-O reference | The 36-character UUID text, once per symbol | A small integer id |
| Addresses | Absolute `start` and `end` | Offset from the Mach-O's `__TEXT` start, plus a size. Most values fit in 2-4 bytes |
| Unnamed functions (`func_<addr>`) | A row in `names` each | No name row. Rebuilt from the address when read |
| Same Mach-O seen again (the same shared cache in another device's IPSW, or a rescan) | All of its symbols are inserted again with new ids | Its symbol list is fingerprinted. A list already stored is skipped, and a list with new symbols only appends the new ones |

## Requirements

- Python 3.14
- The [`ipsw`](https://github.com/blacktop/ipsw) CLI on your `PATH`, which does the scanning (`ipsw symbols --json`)

## Install

```shell
python3 -m pip install -U .
```

## Run the server

```shell
symbolicator-server --db syms.db
```

or `python3 -m symbolicator_server --db syms.db`.

| Option | Default | |
|---|---|---|
| `--db` | (required) | SQLite database file, created if missing |
| `--host` / `--port` | `localhost` / `3993` | Where to listen |
| `--sigs-dir` | | Default kernel signatures dir for scans |
| `--pem-db` | | Default AEA pem DB for scans |
| `--ipsw-bin` | `ipsw` on `PATH` | The ipsw CLI used to scan |
| `-v`, `--verbose` | | Log every image of a scan |

## Scan an IPSW

```shell
curl -X POST "http://localhost:3993/v1/syms/scan?path=/PATH/TO/IPSW.ipsw"
```

The scan runs as a single transaction, and lookups keep working while it runs.
Scanning an IPSW that is already in the database returns `409`. To scan it
again and merge in anything new, use `PUT /v1/syms/rescan?path=...`. Both
accept optional `sig_dir` and `pem_db` query parameters.

## Symbolicate a crash

```shell
ipsw symbolicate --server http://localhost:3993 CRASH-REPORT.ips --proc "SpringBoard"
```