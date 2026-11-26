import dataclasses
import logging
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from starlette.background import BackgroundTask
from starlette.requests import ClientDisconnect

from symbolicator_server._version import __version__
from symbolicator_server.console import setup_server_logging
from symbolicator_server.exceptions import InvalidReportError, IpswAlreadyLoadedError
from symbolicator_server.ips_report import IpsReport
from symbolicator_server.ipsw_scan import IpswScanner
from symbolicator_server.models import API_VERSION, ServerVersion
from symbolicator_server.symbolicator import Symbolicator
from symbolicator_server.symbols_dao import SCHEMA_VERSION, SymbolsDao

NDJSON = "application/x-ndjson"
ROUTE_VERSION = "x-version"

logger = logging.getLogger(__name__)
app = FastAPI(title="symbolicator")


def get(path: str, version: str):
    """
    A GET route of the given MAJOR.MINOR version, which /capabilities tells. A change older clients cannot
    take (a field or parameter removed, renamed or meaning something else) bumps the major, an addition bumps
    the minor: a client calls a route only when the server speaks its major and its minor or a later one.
    """
    return app.get(path, openapi_extra={ROUTE_VERSION: version})


def post(path: str, version: str):
    """ A POST route of the given MAJOR.MINOR version, as get(). """
    return app.post(path, openapi_extra={ROUTE_VERSION: version})


def error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message})


def symbolicate_report(database_path: Path, text: str) -> dict:
    with SymbolsDao.open(database_path) as dao:
        report = Symbolicator(dao).symbolicate(IpsReport.parse(text))
    return dataclasses.asdict(report)


@post("/scan", "1.0")
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


@post("/symbolicate", "1.0")
async def post_symbolicate(request: Request):
    """ Body: an .ips report. Answers the symbolicated report. """
    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    try:
        return await run_in_threadpool(symbolicate_report, request.app.state.database_path, text)
    except InvalidReportError as e:
        return error_response(400, str(e))


@get("/capabilities", "1.0")
def get_capabilities(request: Request):
    """ The version of each route: {route: "MAJOR.MINOR"}. Clients check the one of a route before they call it. """
    # openapi_extra is unset on a route declared without get() or post(), which then fails here
    return {route.path: route.openapi_extra[ROUTE_VERSION] for route in request.app.routes
            if isinstance(route, APIRoute)}


@get("/version", "1.0")
def get_version():
    """ The server's package and database schema versions, and the API version older clients check. """
    return dataclasses.asdict(ServerVersion(__version__, API_VERSION, SCHEMA_VERSION))


@get("/stats", "1.0")
def get_stats(request: Request):
    """ Database size, rows per table, and the loaded IPSWs. """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        return dataclasses.asdict(dao.stats())


# ---------------------------------------------------------------------------
# Symbol lookup. UUIDs match in any case. Kernel addresses go without bit 63, as stored.
# ---------------------------------------------------------------------------


@get("/dsc", "1.0")
def get_dscs(request: Request, device: str, build: str):
    """ The shared caches of a device's build: [{uuid, shared_region_start}]. """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        return [dataclasses.asdict(dsc) for dsc in dao.find_dscs(device, build)]


@get("/dsc/{uuid}/images", "1.0")
def get_dsc_images(request: Request, uuid: str):
    """ The images of a shared cache: [{uuid, path, text_start, text_end}]. """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        if dao.get_shared_region_start(uuid.upper()) is None:
            return error_response(404, f"shared cache {uuid} not found")
        return [dataclasses.asdict(image) for image in dao.get_dsc_images(uuid.upper())]


@get("/kernelcache", "1.0")
def get_kernelcaches(request: Request, device: str, build: str):
    """
    The kernelcaches of a device's build: [{uuid, path, kernel_version}]. For a report which does not tell
    its kernelcache. An IPSW holds several (release and research, one per board): the one a device runs is
    the one whose images hold the kernel images of the report.
    """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        return [dataclasses.asdict(kernelcache) for kernelcache in dao.find_kernelcaches(device, build)]


@get("/kernelcache/{uuid}/images", "1.0")
def get_kernelcache_images(request: Request, uuid: str):
    """ The kexts of a kernelcache, the kernel among them: [{uuid, path, text_start, text_end}]. """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        if dao.get_macho_id(uuid.upper()) is None:
            return error_response(404, f"kernelcache {uuid} not found")
        return [dataclasses.asdict(image) for image in dao.get_kernelcache_images(uuid.upper())]


@get("/images/{uuid}/symbols", "1.0")
def get_image_symbols(request: Request, uuid: str, dsc: Optional[str] = None, kernelcache: Optional[str] = None):
    """
    The functions of an image: [[start, end, name or null]], at the addresses of its copy in the given
    shared cache or kernelcache (without either, of a copy which has symbols).
    """
    with SymbolsDao.open(request.app.state.database_path) as dao:
        copy = dao.find_image_copy(uuid.upper(), dsc.upper() if dsc else None,
                                   kernelcache.upper() if kernelcache else None)
        if copy is None:
            return error_response(404, f"image {uuid} not found")
        # JSONResponse directly: FastAPI's own encoding walks every one of an image's ~100,000s functions
        return JSONResponse([list(symbol) for symbol in dao.get_function_symbols(copy)])


def serve(database_path: Path, signatures: Path, host: str, port: int, verbose: bool = False) -> None:
    """ Run the server until it is stopped. """
    setup_server_logging(verbose)
    scanner = IpswScanner.create(database_path, signatures)
    with SymbolsDao.open(database_path) as dao:
        dao.setup_schema()
    app.state.database_path = database_path
    app.state.scanner = scanner
    uvicorn.run(app, host=host, port=port, log_config=None)  # log_config=None: uvicorn logs through ours too
