import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from symbolicator_server.client import DEFAULT_SERVER, SymbolicatorClient
from symbolicator_server.console import ScanProgress, setup_cli_logging
from symbolicator_server.exceptions import IpswNotInstalledError, NotAnIpswError, ServerError, ServerUnreachableError
from symbolicator_server.ips_report import IpsReport
from symbolicator_server.symbols_dao import SymbolsDao

setup_cli_logging()
logger = logging.getLogger(__name__)

Server = Annotated[str, typer.Option("--server", "-s", envvar="SYMBOLICATOR_SERVER", help="Server URL")]

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, no_args_is_help=True,
                  add_completion=False)


@app.command("serve")
def cli_serve(
        database_path: Annotated[Path, typer.Argument(metavar="DB", help="SQLite database file")],
        signatures: Annotated[Path, typer.Argument(exists=True, file_okay=False, metavar="SIGDIR",
                                                   help="Kernel signatures dir, for scanning IPSWs")],
        host: Annotated[str, typer.Option(help="Address to listen on")] = "localhost",
        port: Annotated[int, typer.Option(help="Port to listen on")] = 3993,
        override_db: Annotated[bool, typer.Option("--override-db",
                                                  help="Replace an existing database with a new, empty one")] = False,
        verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Log every name a scan adds or keeps")] = False,
) -> None:
    """ Run the server, on the database DB (created if it does not exist). """
    if override_db:
        for path in SymbolsDao.delete_files(database_path):
            logger.info(f"Deleted {path}")
    if not database_path.exists():
        logger.info(f"Creating {database_path}")

    from symbolicator_server.server import serve  # fastapi and uvicorn are only needed here
    serve(database_path, signatures.resolve(), host, port, verbose)


@app.command("scan")
def cli_scan(
        ipsw_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, metavar="IPSW", help="The .ipsw")],
        server: Server = DEFAULT_SERVER,
        force: Annotated[bool, typer.Option("--force", "-f", help="Load it again if it is already loaded")] = False,
) -> None:
    """ Send an IPSW to the server, which scans it and loads its symbols into its database. """
    if ipsw_path.suffix.lower() != ".ipsw":
        raise NotAnIpswError(ipsw_path)

    with ScanProgress.start() as status:
        SymbolicatorClient(server).scan(ipsw_path, force, status)


@app.command("symbolicate")
def cli_symbolicate(
        report_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, metavar="REPORT",
                                                    help=".ips report")],
        server: Server = DEFAULT_SERVER,
        proc: Annotated[Optional[str], typer.Option("--proc", "-p", help="Only this process (its name)")] = None,
        all_procs: Annotated[bool, typer.Option("--all", "-a",
                                                help="Every process, not only the panicked one")] = False,
        as_json: Annotated[bool, typer.Option("--json", help="Print the server's JSON")] = False,
) -> None:
    """ Symbolicate a report and print it. """
    report = SymbolicatorClient(server).symbolicate(report_path)
    if as_json:
        json.dump(report, sys.stdout, indent=2)
        return
    ips_report = IpsReport.from_dict(report)
    typer.echo(ips_report.format(proc, all_procs))
    if ips_report.missing_images:
        logger.warning(f"{len(ips_report.missing_images)} images not in the database")


@app.command("stats")
def cli_stats(
        server: Server = DEFAULT_SERVER,
        verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Also list the loaded IPSWs")] = False,
) -> None:
    """ Show what the server's database holds. """
    stats = SymbolicatorClient(server).stats()
    if not verbose:
        stats = stats.without_ipsws()
    typer.echo(stats)


def main() -> None:
    try:
        app()
    except IpswNotInstalledError:
        logger.error("ipsw is not installed, and the server scans IPSWs with it. "
                     "Install it: brew install blacktop/tap/ipsw (https://github.com/blacktop/ipsw)")
    except NotAnIpswError as e:
        logger.error(f"{e.path.name} is not an .ipsw")
    except ServerUnreachableError as e:
        logger.error(f"cannot reach {e.server}: {e.reason}")
    except ServerError as e:
        if e.status_code is None:
            logger.error(e.message)
        else:
            logger.error(f"{e.status_code}: {e.message}")
    sys.exit(1)


if __name__ == "__main__":
    main()
