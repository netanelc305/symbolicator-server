import dataclasses
import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask
from starlette.requests import ClientDisconnect

from symbolicator_server.console import setup_server_logging
from symbolicator_server.exceptions import InvalidReportError, IpswAlreadyLoadedError
from symbolicator_server.ips_report import IpsReport
from symbolicator_server.ipsw_scan import IpswScanner
from symbolicator_server.symbolicator import Symbolicator
from symbolicator_server.symbols_dao import SymbolsDao

NDJSON = "application/x-ndjson"

logger = logging.getLogger(__name__)
app = FastAPI(title="symbolicator")


def error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message})


def symbolicate_report(database_path: Path, text: str) -> dict:
    with SymbolsDao.open(database_path) as dao:
        report = Symbolicator(dao).symbolicate(IpsReport.parse(text))
    return dataclasses.asdict(report)


@app.post("/scan")
async def post_scan(request: Request, name: str, force: bool = False):
    """ Body: an .ipsw. Answers one JSON line per stage, then {"done": counts} or {"error": ...}. """
    scanner = request.app.state.scanner
    scan = scanner.new_scan(name, force)
    try:
        sha1 = await scan.receive(request.stream())
    except ClientDisconnect:
        scan.cleanup()
        logger.warning(f"Upload of {scan.name} cut off by the client, nothing loaded")
        return error_response(400, "upload cut off")

    # checked now, so an IPSW that is already loaded is not scanned for nothing
    if not force and scanner.is_loaded(sha1):
        scan.cleanup()
        logger.info(f"{scan.name}: already in the database")
        return error_response(409, str(IpswAlreadyLoadedError(scan.name, sha1)))

    # From here the answer streams one line per stage and progress update. The folder is removed
    # once the answer ends, also when the client goes away before that.
    return StreamingResponse(scan.stages(), media_type=NDJSON, background=BackgroundTask(scan.cleanup))


@app.post("/symbolicate")
async def post_symbolicate(request: Request):
    """ Body: an .ips report. Answers the symbolicated report. """
    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    try:
        return await run_in_threadpool(symbolicate_report, request.app.state.database_path, text)
    except InvalidReportError as e:
        return error_response(400, str(e))


@app.get("/stats")
def get_stats(request: Request):
    """ Database size, rows per table, and the loaded IPSWs. """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        return dataclasses.asdict(dao.stats())


def serve(database_path: Path, signatures: Path, host: str, port: int, verbose: bool = False) -> None:
    """ Run the server until it is stopped. """
    setup_server_logging(verbose)
    scanner = IpswScanner.create(database_path, signatures)
    with SymbolsDao.open(database_path) as dao:
        dao.create_tables()
    app.state.database_path = database_path
    app.state.scanner = scanner
    uvicorn.run(app, host=host, port=port, log_config=None)  # log_config=None: uvicorn logs through ours too
