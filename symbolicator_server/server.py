"""
A Python stand-in for ipswd's symbol server, storing one all-integer row per
symbol (see store.py).

    symbolicator-server --db syms.db

Same endpoints as ipswd (/v1/...), so `ipsw symbolicate --server` works against it:

    POST /v1/syms/scan?path=<ipsw>[&sig_dir=][&pem_db=]   scan an IPSW into the database
    PUT  /v1/syms/rescan?path=<ipsw>                      scan again, replacing what changed
    GET  /v1/_ping
    GET  /v1/syms/ipsw?version=&build=&device=            is this IPSW scanned?
    GET  /v1/syms/macho/{uuid}                            a Mach-O (path, __TEXT range)
    GET  /v1/syms/dsc/{uuid}                              a dyld_shared_cache
    GET  /v1/syms/dsc/{uuid}/{addr}                       the dylib of a shared cache containing addr
    GET  /v1/syms/{uuid}/{addr}                           the symbol at addr
    GET  /v1/syms/{uuid}                                  all symbols of a Mach-O

Plus one that ipswd does not have:

    GET  /v1/stats                                        database size per table
"""

import argparse
import logging
import os
import shutil

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from symbolicator_server import scanner
from symbolicator_server.store import Store, symbol_json

app = FastAPI(title="symbolicator-server")
STORE = None  # set in main()
CONFIG = {}  # ipsw binary, default signatures dir and pem DB


def error(status, message):
    return JSONResponse(status_code=status, content={"error": message})


def parse_addr(addr):
    """ipswd parses the address with cast.ToUint64: decimal or 0x-hex, anything else is 0.

    SQLite integers are signed 64-bit and stored addresses are below 2**63, so a
    larger address can match nothing: it becomes -1 rather than failing to bind."""
    try:
        n = int(addr, 0)
    except ValueError:
        return 0
    return n if 0 <= n < 1 << 63 else -1


@app.get("/v1/_ping", response_class=PlainTextResponse)
def ping():
    return "OK"


# --------------------------------------------------------------------- scan


def run_scan(request: Request, rescan: bool):
    q = request.query_params
    path = q.get("path")
    if not path:
        return error(400, "missing path query parameter")
    if q.get("device"):
        return error(400, "device-scoped database ingestion is not supported; use device-scoped JSONL export instead")
    try:
        scanner.scan(
            STORE,
            os.path.normpath(path),
            ipsw_bin=CONFIG["ipsw_bin"],
            sigs_dir=q.get("sig_dir") or CONFIG["sigs_dir"],
            pem_db=q.get("pem_db") or CONFIG["pem_db"],
            rescan=rescan,
        )
    except scanner.AlreadyScanned as e:
        return error(409, str(e))
    except Exception as e:  # noqa: BLE001 - ipswd answers 500 with the error text
        logging.exception("scan failed")
        return error(500, str(e))
    return JSONResponse(status_code=201, content={"created": True}) if rescan else {"success": True}


# Plain `def` routes run in FastAPI's thread pool, so lookups keep working during a scan.
@app.post("/v1/syms/scan")
def scan(request: Request):
    return run_scan(request, rescan=False)


@app.put("/v1/syms/rescan")
def rescan(request: Request):
    return run_scan(request, rescan=True)


# ------------------------------------------------------------------- lookups
# Order matters: the fixed paths (ipsw, macho, dsc) must come before /syms/{uuid}.


@app.get("/v1/syms/ipsw")
def get_ipsw(version: str = "", build: str = "", device: str = ""):
    if not (version and build and device):
        return error(400, "version, build and device are required")
    ipsw = STORE.get_ipsw(STORE.reader(), version, build, device)
    return ipsw if ipsw else error(404, "not found")


@app.get("/v1/syms/macho/{uuid}")
def get_macho(uuid: str):
    macho = STORE.get_macho(STORE.reader(), uuid)
    return macho if macho else error(404, "not found")


@app.get("/v1/syms/dsc/{uuid}")
def get_dsc(uuid: str):
    dsc = STORE.get_dsc(STORE.reader(), uuid)
    return dsc if dsc else error(404, "not found")


@app.get("/v1/syms/dsc/{uuid}/{addr}")
def get_dsc_image(uuid: str, addr: str):
    dylib = STORE.get_dsc_image(STORE.reader(), uuid, parse_addr(addr))
    return dylib if dylib else error(404, "not found")


@app.get("/v1/stats")
def stats():
    return STORE.stats(STORE.reader())


@app.get("/v1/syms/{uuid}/{addr}")
def get_symbol(uuid: str, addr: str):
    sym = STORE.get_symbol(STORE.reader(), uuid, parse_addr(addr))
    return symbol_json(*sym) if sym else error(404, "not found")


@app.get("/v1/syms/{uuid}")
def get_symbols(uuid: str):
    syms = STORE.get_symbols(STORE.reader(), uuid)
    return [symbol_json(*s) for s in syms]


# ---------------------------------------------------------------------- main


def main():
    global STORE
    p = argparse.ArgumentParser(description="ipswd-compatible symbol server")
    p.add_argument("--db", required=True, help="sqlite database file")
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=3994)
    p.add_argument("--sigs-dir", help="default kernel signatures dir (ipswd: daemon.sigs-dir)")
    p.add_argument("--pem-db", help="default AEA pem DB (ipswd: daemon.pem-db)")
    p.add_argument("--ipsw-bin", default=shutil.which("ipsw") or "ipsw", help="the ipsw CLI used to scan")
    p.add_argument("-v", "--verbose", action="store_true", help="log every image of a scan")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    STORE = Store(args.db)
    CONFIG.update(ipsw_bin=args.ipsw_bin, sigs_dir=args.sigs_dir, pem_db=args.pem_db)
    logging.info("database %s, scanning with %s", args.db, args.ipsw_bin)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
