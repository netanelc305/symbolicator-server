import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

from symbolicator_server.exceptions import DatabaseVersionError
from symbolicator_server.models import DatabaseStats, FunctionSymbol, Image, ImageInfo, ImageRecord, Ipsw, IpswStats, \
    Kernelcache, SharedCache, SymbolMatch

SCHEMA = Path(__file__).parent / "schema.sql"
SCHEMA_VERSION = 1  # Bump on every schema change
SQLITE_SIDE_FILES = ["-wal", "-shm"]
TABLES = ["ipsw", "dsc", "image", "ipsw_image", "kernelcache_kext", "macho", "symbol", "name"]
IMAGE_COLUMNS = ("image.id, image.macho_id, image.kind, image.path, image.text_start, image.text_size, "
                 "image.dsc_uuid, image.cpu, image.arch, image.kernel_version, image.offset_base")
ROWS_PER_INSERT = 100_000
NAMES_PER_QUERY = 10_000  # SQLite allows only so many values in one query
WHITESPACE = re.compile(r"\s+")


class SymbolsDao:
    """
    All the queries on the symbols database.

    Writes are not committed until commit() is called; closing without it drops them.
    """

    def __init__(self, path: Path, connection: sqlite3.Connection):
        self.path = path
        self.connection = connection

    @classmethod
    def open(cls, path: Path) -> "SymbolsDao":
        # A scan's answer is streamed by worker threads, which may take turns on its connection.
        return cls(path, sqlite3.connect(path, check_same_thread=False))

    @staticmethod
    def delete_files(path: Path) -> list[Path]:
        """ Delete the database and SQLite's side files; returns the deleted ones. """
        deleted = []
        for file in [path] + [Path(f"{path}{suffix}") for suffix in SQLITE_SIDE_FILES]:
            if not file.exists():
                continue
            file.unlink()
            deleted.append(file)
        return deleted

    def get_schema_version(self) -> int:
        """ The schema version saved in the database file; 0 for a new database or one made before versions. """
        return self.connection.execute("PRAGMA user_version").fetchone()[0]

    def setup_schema(self) -> None:
        """ Create the tables of a new database, or verify an existing one has the schema this code reads. """
        version = self.get_schema_version()
        if version == 0 and self._is_empty():
            self._create_tables()
            return
        if version == 0 and self._matches_schema():
            # made before databases had a version, but with this very schema
            self._set_schema_version(SCHEMA_VERSION)
            return
        if version != SCHEMA_VERSION:
            raise DatabaseVersionError(self.path, version, SCHEMA_VERSION)

    def _create_tables(self) -> None:
        self.connection.executescript(SCHEMA.read_text())
        # WAL lets symbolication read the database while a scan is writing to it.
        # The setting is saved in the database file, so setting it once is enough.
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._set_schema_version(SCHEMA_VERSION)

    def _set_schema_version(self, version: int) -> None:
        self.connection.execute(f"PRAGMA user_version = {version}")  # a pragma takes no ? parameters
        self.connection.commit()

    def _is_empty(self) -> bool:
        return self.connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0

    def _matches_schema(self) -> bool:
        """ Whether the database has exactly the tables and indexes schema.sql creates. """
        expected = sqlite3.connect(":memory:")
        expected.executescript(SCHEMA.read_text())
        matches = get_schema_statements(expected) == get_schema_statements(self.connection)
        expected.close()
        return matches

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def checkpoint(self) -> None:
        """
        Move the WAL file's contents into the database and empty it.

        A load is one big transaction, so it first goes into the WAL file (gigabytes). SQLite moves
        it over only now and then; doing it right after a load keeps the disk usage honest.
        """
        self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # ---------------------------------------------------------------------------
    # IPSWs and shared caches
    # ---------------------------------------------------------------------------

    def get_ipsw_by_sha1(self, sha1: str) -> Optional[Ipsw]:
        row = self.connection.execute(
            "SELECT id, sha1, name, version, build, platform, devices FROM ipsw WHERE sha1 = ?", (sha1,)).fetchone()
        if row is None:
            return None
        ipsw_id, sha1, name, version, build, platform, devices = row
        return Ipsw(ipsw_id, sha1, name, version, build, platform, json.loads(devices))

    def is_ipsw_loaded(self, sha1: str) -> bool:
        return self.connection.execute("SELECT 1 FROM ipsw WHERE sha1 = ?", (sha1,)).fetchone() is not None

    def add_ipsw(self, sha1: str, name: str, version: str, build: str, platform: Optional[str],
                 devices: list[str]) -> Ipsw:
        ipsw_id = self.connection.execute(
            "INSERT INTO ipsw (sha1, name, version, build, platform, devices) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            (sha1, name, version, build, platform, json.dumps(devices))).fetchone()[0]
        return Ipsw(ipsw_id, sha1, name, version, build, platform, devices)

    def delete_ipsw(self, ipsw_id: int) -> None:
        """
        Remove an IPSW, its caches, the images no other IPSW has, and the UUIDs no image has.

        The symbols of a UUID that other IPSWs also have stay: they are shared, and what this IPSW
        added to them cannot be told apart from what the others did.
        """
        self.connection.execute("DELETE FROM ipsw_image WHERE ipsw_id = ?", (ipsw_id,))
        self.connection.execute("DELETE FROM dsc WHERE ipsw_id = ?", (ipsw_id,))
        self.connection.execute("DELETE FROM ipsw WHERE id = ?", (ipsw_id,))

        self.connection.execute("DELETE FROM image WHERE id NOT IN (SELECT image_id FROM ipsw_image)")
        self.connection.execute("DELETE FROM kernelcache_kext WHERE image_id NOT IN (SELECT id FROM image)")

        self.connection.execute(
            "DELETE FROM symbol WHERE macho_id IN "
            "(SELECT id FROM macho WHERE id NOT IN (SELECT macho_id FROM image))")
        self.connection.execute(
            "DELETE FROM kernelcache_kext WHERE kernelcache_id NOT IN (SELECT macho_id FROM image)")
        self.connection.execute("DELETE FROM macho WHERE id NOT IN (SELECT macho_id FROM image)")

    def add_dsc(self, ipsw_id: int, uuid: str, shared_region_start: int) -> None:
        self.connection.execute("INSERT INTO dsc (ipsw_id, uuid, shared_region_start) VALUES (?, ?, ?)",
                                (ipsw_id, uuid, shared_region_start))

    def get_shared_region_start(self, dsc_uuid: str) -> Optional[int]:
        row = self.connection.execute(
            "SELECT shared_region_start FROM dsc WHERE uuid = ? LIMIT 1", (dsc_uuid,)).fetchone()
        if row is None:
            return None
        return row[0]

    # ---------------------------------------------------------------------------
    # UUIDs and images
    # ---------------------------------------------------------------------------

    def get_macho_id(self, uuid: str) -> Optional[int]:
        row = self.connection.execute("SELECT id FROM macho WHERE uuid = ?", (uuid,)).fetchone()
        if row is None:
            return None
        return row[0]

    def add_macho(self, uuid: str) -> int:
        """ Add the UUID; returns its id. """
        return self.connection.execute("INSERT INTO macho (uuid) VALUES (?) RETURNING id", (uuid,)).fetchone()[0]

    def find_image(self, macho_id: int, record: ImageRecord) -> Optional[Image]:
        """ The stored image that is this record: same UUID, path, kind and place. """
        row = self.connection.execute(
            f"SELECT {IMAGE_COLUMNS} FROM image "
            f"WHERE macho_id = ? AND path = ? AND kind = ? AND text_start = ? AND text_size = ? AND dsc_uuid IS ? "
            f"LIMIT 1",
            (macho_id, record.path, record.kind, record.text_start, record.text_size, record.dsc_uuid)).fetchone()
        if row is None:
            return None
        return Image.from_row(row)

    def add_image(self, macho_id: int, record: ImageRecord, offset_base: Optional[int]) -> Image:
        image_id = self.connection.execute(
            "INSERT INTO image (macho_id, kind, path, text_start, text_size, dsc_uuid, cpu, arch, kernel_version, "
            "offset_base) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (macho_id, record.kind, record.path, record.text_start, record.text_size, record.dsc_uuid, record.cpu,
             record.arch, record.kernel_version, offset_base)).fetchone()[0]
        return Image(image_id, macho_id, record.kind, record.path, record.text_start, record.text_size,
                     record.dsc_uuid, record.cpu, record.arch, record.kernel_version, offset_base)

    def link_ipsw_image(self, ipsw_id: int, image_id: int) -> None:
        """ Mark the image as in the IPSW (once: an IPSW can list the very same image twice). """
        self.connection.execute("INSERT OR IGNORE INTO ipsw_image (ipsw_id, image_id) VALUES (?, ?)",
                                (ipsw_id, image_id))

    def link_kernelcache_kext(self, kernelcache_id: int, image_id: int) -> None:
        self.connection.execute("INSERT OR IGNORE INTO kernelcache_kext (kernelcache_id, image_id) VALUES (?, ?)",
                                (kernelcache_id, image_id))

    def get_images_by_uuid(self, uuid: str) -> list[Image]:
        """ Every stored copy of the UUID. """
        rows = self.connection.execute(
            f"SELECT {IMAGE_COLUMNS} FROM image JOIN macho ON image.macho_id = macho.id WHERE macho.uuid = ?",
            (uuid,)).fetchall()
        return [Image.from_row(row) for row in rows]

    def get_kernelcache_kexts(self, kernelcache_uuid: str) -> list[Image]:
        """ The kext images of a fileset kernelcache. """
        rows = self.connection.execute(
            f"SELECT {IMAGE_COLUMNS} FROM image "
            f"JOIN kernelcache_kext ON kernelcache_kext.image_id = image.id "
            f"JOIN macho ON kernelcache_kext.kernelcache_id = macho.id "
            f"WHERE macho.uuid = ?",
            (kernelcache_uuid,)).fetchall()
        return [Image.from_row(row) for row in rows]

    def find_dscs(self, device: str, build: str) -> list[SharedCache]:
        """ The shared caches of the IPSWs of this build that list this device. """
        rows = self.connection.execute(
            "SELECT DISTINCT dsc.uuid, dsc.shared_region_start FROM dsc JOIN ipsw ON dsc.ipsw_id = ipsw.id "
            "WHERE ipsw.build = ? AND EXISTS (SELECT 1 FROM json_each(ipsw.devices) WHERE json_each.value = ?) "
            "ORDER BY dsc.uuid",
            (build, device)).fetchall()
        return [SharedCache(*row) for row in rows]

    def find_kernelcaches(self, device: str, build: str) -> list[Kernelcache]:
        """ The kernelcaches of the IPSWs of this build that list this device. """
        rows = self.connection.execute(
            "SELECT DISTINCT macho.uuid, image.path, image.kernel_version FROM image "
            "JOIN macho ON image.macho_id = macho.id "
            "JOIN ipsw_image ON ipsw_image.image_id = image.id JOIN ipsw ON ipsw_image.ipsw_id = ipsw.id "
            "WHERE image.kind = 'kernel' AND ipsw.build = ? "
            "AND EXISTS (SELECT 1 FROM json_each(ipsw.devices) WHERE json_each.value = ?) "
            "ORDER BY image.path, macho.uuid",
            (build, device)).fetchall()
        return [Kernelcache(*row) for row in rows]

    def get_dsc_images(self, dsc_uuid: str) -> list[ImageInfo]:
        """ The images of a shared cache, by address. """
        rows = self.connection.execute(
            "SELECT DISTINCT macho.uuid, image.path, image.text_start, image.text_start + image.text_size "
            "FROM image JOIN macho ON image.macho_id = macho.id WHERE image.dsc_uuid = ? ORDER BY image.text_start",
            (dsc_uuid,)).fetchall()
        return [ImageInfo(*row) for row in rows]

    def get_kernelcache_images(self, kernelcache_uuid: str) -> list[ImageInfo]:
        """ The kext images of a fileset kernelcache (the kernel itself among them), by address. """
        rows = self.connection.execute(
            "SELECT DISTINCT kext.uuid, image.path, image.text_start, image.text_start + image.text_size "
            "FROM image JOIN macho AS kext ON image.macho_id = kext.id "
            "JOIN kernelcache_kext ON kernelcache_kext.image_id = image.id "
            "JOIN macho AS kernelcache ON kernelcache_kext.kernelcache_id = kernelcache.id "
            "WHERE kernelcache.uuid = ? ORDER BY image.text_start",
            (kernelcache_uuid,)).fetchall()
        return [ImageInfo(*row) for row in rows]

    def find_image_copy(self, uuid: str, dsc_uuid: Optional[str] = None,
                        kernelcache_uuid: Optional[str] = None) -> Optional[Image]:
        """
        The copy of the UUID in the given shared cache or kernelcache; without either, a copy which has symbols.
        """
        if dsc_uuid is not None:
            where = "macho.uuid = ? AND image.dsc_uuid = ?"
            params: tuple = (uuid, dsc_uuid)
        elif kernelcache_uuid is not None:
            where = ("macho.uuid = ? AND image.id IN (SELECT kernelcache_kext.image_id FROM kernelcache_kext "
                     "JOIN macho AS kernelcache ON kernelcache_kext.kernelcache_id = kernelcache.id "
                     "WHERE kernelcache.uuid = ?)")
            params = (uuid, kernelcache_uuid)
        else:
            where = "macho.uuid = ?"
            params = (uuid,)
        row = self.connection.execute(
            f"SELECT {IMAGE_COLUMNS} FROM image JOIN macho ON image.macho_id = macho.id WHERE {where} "
            f"ORDER BY image.offset_base IS NULL, image.id LIMIT 1",
            params).fetchone()
        if row is None:
            return None
        return Image.from_row(row)

    def find_dylib_in_cache(self, dsc_uuid: str, address: int) -> Optional[Image]:
        """ The dylib of the given shared cache whose __TEXT contains address. """
        row = self.connection.execute(
            f"SELECT {IMAGE_COLUMNS} FROM image "
            f"WHERE dsc_uuid = ? AND text_start <= ? AND text_start + text_size > ? LIMIT 1",
            (dsc_uuid, address, address)).fetchone()
        if row is None:
            return None
        return Image.from_row(row)

    # ---------------------------------------------------------------------------
    # Symbols and names
    # ---------------------------------------------------------------------------

    def get_symbols(self, macho_id: int) -> dict[int, Optional[int]]:
        """ {offset: name_id} of the symbols a UUID has. """
        symbols = {}
        for offset, name_id in self.connection.execute(
                'SELECT "offset", name_id FROM symbol WHERE macho_id = ?', (macho_id,)):
            symbols[offset] = name_id
        return symbols

    def add_symbols(self, rows: list[tuple[int, int, int, Optional[int]]]) -> None:
        """ Add (macho_id, offset, size, name_id) rows. """
        for rows_chunk in chunks(rows, ROWS_PER_INSERT):
            self.connection.executemany('INSERT INTO symbol (macho_id, "offset", size, name_id) VALUES (?, ?, ?, ?)',
                                        rows_chunk)

    def set_symbol_names(self, rows: list[tuple[int, int, int]]) -> None:
        """ Set the names of symbols, from (name_id, macho_id, offset) rows. """
        self.connection.executemany('UPDATE symbol SET name_id = ? WHERE macho_id = ? AND "offset" = ?', rows)

    def find_symbol(self, macho_id: int, offset: int) -> Optional[SymbolMatch]:
        """ The function of the UUID covering the offset. If several do, the one starting closest to it. """
        row = self.connection.execute(
            'SELECT symbol."offset", name.text FROM symbol LEFT OUTER JOIN name ON symbol.name_id = name.id '
            'WHERE symbol.macho_id = ? AND symbol."offset" <= ? AND symbol."offset" + symbol.size > ? '
            'ORDER BY symbol."offset" DESC LIMIT 1',
            (macho_id, offset, offset)).fetchone()
        if row is None:
            return None
        return SymbolMatch(*row)

    def get_function_symbols(self, copy: Image) -> list[FunctionSymbol]:
        """
        All functions of this image, sorted by address.

        The DB stores functions as offsets, shared by every copy of the same binary. They are returned
        as absolute addresses in this copy (offset_base + offset).
        """
        if copy.offset_base is None:
            return []  # this copy could not be lined up with its UUID's symbols
        rows = self.connection.execute(
            'SELECT symbol."offset", symbol.size, name.text FROM symbol '
            'LEFT OUTER JOIN name ON symbol.name_id = name.id WHERE symbol.macho_id = ? ORDER BY symbol."offset"',
            (copy.macho_id,))
        return [FunctionSymbol(copy.offset_base + offset, copy.offset_base + offset + size, name)
                for offset, size, name in rows]

    def get_name_text(self, name_id: int) -> str:
        return self.connection.execute("SELECT text FROM name WHERE id = ?", (name_id,)).fetchone()[0]

    def get_name_ids(self, names: set[str]) -> dict[str, int]:
        """ {name: id} for the given names, adding the ones the name table does not have yet. """
        name_ids = {}
        for names_chunk in chunks(sorted(names), NAMES_PER_QUERY):
            hashes = {}
            for name in names_chunk:
                hashes[name] = name_hash(name)
            self._find_names(hashes, name_ids)

            missing = []
            for name in names_chunk:
                if name not in name_ids:
                    missing.append((name, hashes[name]))
            if missing:
                self.connection.executemany("INSERT INTO name (text, hash) VALUES (?, ?)", missing)
                self._find_names(hashes, name_ids)
        return name_ids

    def _find_names(self, hashes: dict[str, int], name_ids: dict[str, int]) -> None:
        """ Add {name: id} to name_ids for the names of hashes ({name: hash}) the name table has. """
        placeholders = ", ".join("?" * len(hashes))
        query = f"SELECT id, text FROM name WHERE hash IN ({placeholders})"
        for name_id, text in self.connection.execute(query, list(hashes.values())):
            # another name can have the same hash: only an exact text match counts
            if text in hashes:
                name_ids[text] = name_id

    # ---------------------------------------------------------------------------
    # Stats
    # ---------------------------------------------------------------------------

    def stats(self) -> DatabaseStats:
        """ Database file size, rows per table, and the loaded IPSWs. """
        size = 0
        for file in [self.path, Path(f"{self.path}-wal")]:
            if file.exists():
                size += file.stat().st_size

        rows = {}
        for table in TABLES:
            rows[table] = self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

        images_per_ipsw = {}
        for ipsw_id, count in self.connection.execute("SELECT ipsw_id, count(*) FROM ipsw_image GROUP BY ipsw_id"):
            images_per_ipsw[ipsw_id] = count

        ipsws = []
        for ipsw_id, name, version, build, devices in self.connection.execute(
                "SELECT id, name, version, build, devices FROM ipsw ORDER BY name"):
            ipsws.append(IpswStats(name, version, build, json.loads(devices), images_per_ipsw.get(ipsw_id, 0)))

        return DatabaseStats(str(self.path.absolute()), size, rows, ipsws)

    def __enter__(self) -> "SymbolsDao":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} PATH:{self.path}>"


def name_hash(text: str) -> int:
    """ The first 8 bytes of the name's sha1, as a number SQLite can store (signed 64 bits). """
    digest = hashlib.sha1(text.encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def chunks(items: list, size: int) -> Iterator[list]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def get_schema_statements(connection: sqlite3.Connection) -> list[str]:
    """ The CREATE statements of the database's tables and indexes, without whitespace. """
    statements = []
    for (sql,) in connection.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"):
        # SQLite keeps each statement as it was written: the same table can be written spaced differently
        statements.append(WHITESPACE.sub("", sql))
    return statements
