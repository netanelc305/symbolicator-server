import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Union

from plumbum import local
from plumbum.commands.processes import CommandNotFound
from plumbum.machines import LocalCommand

from symbolicator_server.exceptions import IpswAlreadyLoadedError, IpswNotInstalledError, ScannerOutputError
from symbolicator_server.loader import IpswLoader
from symbolicator_server.symbols_dao import SymbolsDao

logger = logging.getLogger(__name__)


class IpswScanner:
    """ Scans uploaded IPSWs with `ipsw symbols` into the database. The server has one. """

    def __init__(self, database_path: Path, ipsw: LocalCommand, signatures: Path):
        self.database_path = database_path
        self.ipsw = ipsw
        self.signatures = signatures

    @classmethod
    def create(cls, database_path: Path, signatures: Path) -> "IpswScanner":
        """ Find the ipsw tool on the system. """
        try:
            ipsw = local["ipsw"]
        except CommandNotFound:
            raise IpswNotInstalledError() from None
        return cls(database_path, ipsw, signatures)

    def new_scan(self, name: str, force: bool) -> "IpswScan":
        """ Start a scan of an uploaded IPSW, in its own temporary folder. """
        ipsw_path = Path(tempfile.mkdtemp()) / Path(name).name
        return IpswScan(self, ipsw_path, force)

    def is_loaded(self, sha1: str) -> bool:
        with SymbolsDao.open(self.database_path) as dao:
            return dao.is_ipsw_loaded(sha1)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} IPSW:{self.ipsw} DB:{self.database_path}>"


class IpswScan:
    """
    One uploaded IPSW, scanned with `ipsw symbols` and loaded into the database.

    The IPSW is only kept while it is scanned, in its own temporary folder, under its own name:
    the scanner names the IPSW in the database after its file.
    """

    def __init__(self, scanner: IpswScanner, ipsw_path: Path, force: bool):
        self.scanner = scanner
        self.ipsw_path = ipsw_path
        self.force = force

    @property
    def name(self) -> str:
        return self.ipsw_path.name

    @property
    def folder(self) -> Path:
        return self.ipsw_path.parent

    async def receive(self, chunks: AsyncIterator[bytes]) -> str:
        """ Save the uploaded IPSW; returns its sha1, the scanner's id of the IPSW. """
        logger.info(f"{self.name}: receiving")
        sha1 = hashlib.sha1()
        received = 0
        with self.ipsw_path.open("wb") as f:
            async for chunk in chunks:
                f.write(chunk)
                sha1.update(chunk)
                received += len(chunk)
        logger.info(f"{self.name}: received {received / 1e9:.1f} GB")
        return sha1.hexdigest()

    def stages(self) -> Iterator[str]:
        """
        Scan the IPSW, yielding a JSON line as each stage starts.

        ipsw's output is loaded into the database as ipsw writes it, and only saved once ipsw has
        finished without an error. Run by the streaming response in a worker thread, so the blocking
        steps do not stop the server.
        """
        command = self.scanner.ipsw["symbols", "--json", "--signatures", self.scanner.signatures, self.ipsw_path]
        logger.info(command)
        yield stage_line("stage", "extracting symbols (ipsw symbols) and loading them into the database")

        # stderr goes to a file: a full stderr pipe nobody reads would stop ipsw
        with (self.folder / "ipsw-stderr.txt").open("w+") as stderr, SymbolsDao.open(self.scanner.database_path) as dao:
            # ipsw decrypts the IPSW's disk images into $TMPDIR under fixed names, so two scans of the same
            # IPSW would share them and break each other. Each scan gets its own: the IPSW's temporary folder.
            process = command.with_env(TMPDIR=str(self.folder)).popen(stdout=subprocess.PIPE, stderr=stderr, text=True)
            assert process.stdout is not None  # always set with stdout=PIPE
            loader = IpswLoader(dao, self.force)
            load_error = None
            try:
                for counts in loader.load(process.stdout):
                    yield stage_line("progress", counts)
            except (IpswAlreadyLoadedError, ScannerOutputError) as e:
                load_error = str(e)

            # Let ipsw run to its end even when loading failed: stopping it midway leaves its disk
            # images mounted.
            yield stage_line("stage", "waiting for ipsw to finish")
            for _ in process.stdout:
                pass
            process.wait()

            if process.returncode != 0:
                # ipsw failed, so its output may be cut short: nothing of it is saved
                stderr.seek(0)
                message = stderr.read().strip()
                logger.error(f"{self.name}: ipsw failed, nothing saved: {message}")
                yield stage_line("error", message)
                return
            if load_error is not None:
                logger.error(f"{self.name}: loading failed, nothing saved: {load_error}")
                yield stage_line("error", load_error)
                return

            yield stage_line("stage", "saving")
            dao.commit()
            dao.checkpoint()

        counts = loader.counts
        logger.info(f"{self.name}: saved, {counts['image']:,} images, {counts['symbol']:,} symbols")
        yield stage_line("done", counts)

    def cleanup(self) -> None:
        """ Delete the scan's temporary folder. """
        shutil.rmtree(self.folder)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} PATH:{self.ipsw_path}>"


def stage_line(key: str, value: Union[str, dict]) -> str:
    return json.dumps({key: value}) + "\n"
