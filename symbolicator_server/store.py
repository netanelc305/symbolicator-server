"""
Symbol storage: normalized tables, one all-integer row per symbol.

    ipsws, ipsw_devices, dyld_shared_caches, ipsw_dscs,
    machos, ipsw_machos, dsc_images                               what was scanned
    names     (id, name)                                          name -> id
    macho_ids (id, uuid, base, max_size, next_seq)                uuid -> small integer id
    symbols   (macho_id, off, seq, size, name_code)  WITHOUT ROWID one row per symbol
    symbol_lists (macho_id, list_hash)                            fingerprints of merged lists

Why it is small:
  * The Mach-O is referenced by a small integer instead of its 36-character UUID.
  * The address is stored as an offset from the Mach-O's __TEXT start and the
    end as a size, so most values fit in 2-4 bytes (SQLite stores integers in
    1-8 bytes as needed).
  * WITHOUT ROWID: the rows live directly in the primary-key B-tree, so there
    is no second index holding the same columns again.
  * A list a scan delivers is fingerprinted first; a list already merged
    (another device's IPSW, a rescan) writes nothing.
  * Placeholder names (func_<address>) are not stored (name_code 0 / 1).

Same answers as ipswd: a Mach-O's symbols only grow (new lists are merged in),
and when several symbols cover an address the first inserted (lowest seq)
wins, like ipswd's ORDER BY id.

The schema is a simplified version of ipswd's. The kernelcache -> kext and
ipsw -> file-system links are folded into one ipsw_machos table, because they
do not affect how symbols are stored.
"""

import hashlib
import json
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS ipsws (
    id       TEXT PRIMARY KEY,          -- sha1 of the .ipsw file
    name     TEXT,
    version  TEXT,
    build    TEXT,
    platform TEXT
);
CREATE TABLE IF NOT EXISTS ipsw_devices (
    ipsw_id TEXT,
    device  TEXT,
    PRIMARY KEY (ipsw_id, device)
);
CREATE TABLE IF NOT EXISTS dyld_shared_caches (
    uuid                TEXT PRIMARY KEY,
    shared_region_start INTEGER
);
CREATE TABLE IF NOT EXISTS ipsw_dscs (
    ipsw_id  TEXT,
    dsc_uuid TEXT,
    PRIMARY KEY (ipsw_id, dsc_uuid)
);
CREATE TABLE IF NOT EXISTS machos (
    uuid       TEXT PRIMARY KEY,
    kind       TEXT,                    -- kernel / kext / dylib / macho
    path       TEXT,
    text_start INTEGER,
    text_end   INTEGER
);
CREATE TABLE IF NOT EXISTS ipsw_machos (
    ipsw_id    TEXT,
    macho_uuid TEXT,
    PRIMARY KEY (ipsw_id, macho_uuid)
);
CREATE TABLE IF NOT EXISTS dsc_images (
    dsc_uuid   TEXT,
    macho_uuid TEXT,
    PRIMARY KEY (dsc_uuid, macho_uuid)
);
CREATE TABLE IF NOT EXISTS names (
    id   INTEGER PRIMARY KEY,
    name TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS macho_ids (
    id       INTEGER PRIMARY KEY,
    uuid     TEXT UNIQUE,
    base     INTEGER,      -- the Mach-O's __TEXT start; symbol addresses are stored relative to it
    max_size INTEGER,      -- its largest symbol; bounds how far back a lookup has to look
    next_seq INTEGER       -- insertion counter: keeps "first inserted wins" like the old ids
);
CREATE TABLE IF NOT EXISTS symbols (
    macho_id  INTEGER,
    off       INTEGER,     -- start - base
    seq       INTEGER,     -- insertion order within the Mach-O
    size      INTEGER,     -- end - start
    name_code INTEGER,     -- 0/1 = func_ placeholder, otherwise names.id + 2
    PRIMARY KEY (macho_id, off, seq)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS symbol_lists (
    macho_id  INTEGER,
    list_hash BLOB,
    PRIMARY KEY (macho_id, list_hash)
) WITHOUT ROWID;
"""

HIGH_BIT = 1 << 63  # cleared from kernel addresses, but still part of their func_ names

# name_code: 0 and 1 are placeholders, real names are names.id + 2.
NAME_FUNC = 0  # func_<start>                (dylibs, file-system Mach-Os)
NAME_FUNC_KERNEL = 1  # func_<start | bit 63>       (kernel and kexts)
FIRST_REAL_NAME = 2

LIST_HASH_VERSION = b"\x02"  # part of every stored fingerprint; changing it re-merges every list


def placeholder_code(name, start):
    """NAME_FUNC / NAME_FUNC_KERNEL if name is the func_ placeholder for start, else None."""
    if name.startswith("func_"):
        if name == f"func_{start:x}":
            return NAME_FUNC
        if name == f"func_{start | HIGH_BIT:x}":
            return NAME_FUNC_KERNEL
    return None


def decode_name(code, start, name):
    """(name_id, name) from a stored name_code and the name joined from the names table."""
    if code == NAME_FUNC:
        return None, f"func_{start:x}"
    if code == NAME_FUNC_KERNEL:
        return None, f"func_{start | HIGH_BIT:x}"
    return code - FIRST_REAL_NAME, name


def list_hash(symbols):
    """Fingerprint of one symbol list as a scan delivered it (addresses + name text, in order)."""
    text = "".join(f"{start}:{end}:{name}\n" for start, end, name in symbols)
    return hashlib.sha256(LIST_HASH_VERSION + text.encode()).digest()


# Symbols of one Mach-O as (name_id, name, start, end), by address then insertion order.
SYMBOLS_SQL = """
    SELECT m.base + s.off, s.size, s.name_code, n.name
    FROM macho_ids m
    JOIN symbols s     ON s.macho_id = m.id
    LEFT JOIN names n  ON n.id = s.name_code - 2
    WHERE m.uuid = ?
    ORDER BY s.off, s.seq
"""

# Only symbols starting within max_size before addr can cover it: a short range
# scan of the primary key, then the first inserted among the matches.
SYMBOL_AT_SQL = """
    SELECT m.base + s.off, s.size, s.name_code, n.name
    FROM macho_ids m
    JOIN symbols s     ON s.macho_id = m.id
                      AND s.off BETWEEN :addr - m.base - m.max_size AND :addr - m.base
    LEFT JOIN names n  ON n.id = s.name_code - 2
    WHERE m.uuid = :uuid AND :addr - m.base < s.off + s.size
    ORDER BY s.seq LIMIT 1
"""


class Store:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")  # persistent: lookups keep working while a scan writes
            conn.executescript(SCHEMA)

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=60)
        conn.execute("PRAGMA synchronous = NORMAL")  # durable enough under WAL, much faster commits
        conn.execute("PRAGMA cache_size = -65536")  # 64 MiB page cache
        conn.execute("PRAGMA mmap_size = 1073741824")  # read pages straight from the mapped file
        return conn

    def reader(self):
        """A connection for lookups, one per thread and kept open (FastAPI reuses its pool threads)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._local.conn = self.connect()
        return conn

    # ------------------------------------------------------------------ saving

    def has_ipsw(self, conn, ipsw_id):
        return conn.execute("SELECT 1 FROM ipsws WHERE id = ?", (ipsw_id,)).fetchone() is not None

    def save_ipsw(self, conn, rec):
        conn.execute(
            "INSERT OR REPLACE INTO ipsws (id, name, version, build, platform) VALUES (?, ?, ?, ?, ?)",
            (rec["id"], rec["name"], rec["version"], rec["build"], rec.get("platform")),
        )
        conn.executemany(
            "INSERT OR IGNORE INTO ipsw_devices (ipsw_id, device) VALUES (?, ?)",
            [(rec["id"], dev) for dev in rec.get("devices", [])],
        )

    def save_dsc(self, conn, ipsw_id, rec):
        conn.execute(
            "INSERT OR IGNORE INTO dyld_shared_caches (uuid, shared_region_start) VALUES (?, ?)",
            (rec["uuid"], rec["shared_region_start"]),
        )
        conn.execute("INSERT OR IGNORE INTO ipsw_dscs VALUES (?, ?)", (ipsw_id, rec["uuid"]))

    def save_image(self, conn, ipsw_id, image, symbols):
        """Save one Mach-O and its symbols. symbols: [(start, end, name), ...]. Returns a note for the scan log."""
        uuid = image["uuid"]
        conn.execute(
            "INSERT OR IGNORE INTO machos (uuid, kind, path, text_start, text_end) VALUES (?, ?, ?, ?, ?)",
            (uuid, image["kind"], image["path"], image["text_start"], image["text_end"]),
        )
        conn.execute("INSERT OR IGNORE INTO ipsw_machos VALUES (?, ?)", (ipsw_id, uuid))
        if image.get("dsc_uuid"):
            conn.execute("INSERT OR IGNORE INTO dsc_images VALUES (?, ?)", (image["dsc_uuid"], uuid))
        return self.save_symbols(conn, uuid, symbols)

    def save_symbols(self, conn, uuid, symbols):
        macho_id, base, max_size, next_seq = self._macho_id(conn, uuid)
        fingerprint = list_hash(symbols)
        seen = conn.execute(
            "SELECT 1 FROM symbol_lists WHERE macho_id = ? AND list_hash = ?", (macho_id, fingerprint)
        ).fetchone()
        if seen:
            return "already stored, skipped"  # this exact list was merged before: nothing to write
        conn.execute("INSERT INTO symbol_lists (macho_id, list_hash) VALUES (?, ?)", (macho_id, fingerprint))

        # Encode first, then merge in encoded form: stored rows stay, rows not stored yet are
        # appended after them. Comparing (off, size, name_code) needs no join with names.
        codes = [placeholder_code(name, start) for start, _, name in symbols]
        ids = self.name_ids(conn, {sym[2] for sym, code in zip(symbols, codes) if code is None})
        known = (
            set(conn.execute("SELECT off, size, name_code FROM symbols WHERE macho_id = ?", (macho_id,)))
            if next_seq
            else set()
        )
        rows = []
        for (start, end, name), code in zip(symbols, codes):
            # an inverted range is stored with size 0 and never matches, as in ipswd
            key = (start - base, max(end - start, 0), ids[name] + FIRST_REAL_NAME if code is None else code)
            if key not in known:
                known.add(key)
                rows.append((macho_id, key[0], next_seq + len(rows), key[1], key[2]))
                max_size = max(max_size, key[1])
        if not rows:
            return "already stored, skipped" if next_seq else "no symbols"

        conn.executemany("INSERT INTO symbols (macho_id, off, seq, size, name_code) VALUES (?, ?, ?, ?, ?)", rows)
        conn.execute(
            "UPDATE macho_ids SET max_size = ?, next_seq = ? WHERE id = ?", (max_size, next_seq + len(rows), macho_id)
        )
        if next_seq:
            return f"merged {len(rows)} new symbols into the {next_seq} stored"
        return f"inserted {len(rows)} symbol rows"

    def _macho_id(self, conn, uuid):
        """(id, base, max_size, next_seq) for uuid, creating the id on first sight."""
        row = conn.execute("SELECT id, base, max_size, next_seq FROM macho_ids WHERE uuid = ?", (uuid,)).fetchone()
        if row:
            return row
        cur = conn.execute(
            """INSERT INTO macho_ids (uuid, base, max_size, next_seq)
               SELECT uuid, COALESCE(text_start, 0), 0, 0 FROM machos WHERE uuid = ?
               RETURNING id, base, max_size, next_seq""",
            (uuid,),
        )
        return cur.fetchone()

    def name_ids(self, conn, names):
        """Insert the names that are missing and return {name: id}."""
        if not names:
            return {}
        names = json.dumps(list(names))  # one bound parameter, however many names
        conn.execute("INSERT OR IGNORE INTO names (name) SELECT value FROM json_each(?)", (names,))
        return {
            name: nid
            for nid, name in conn.execute(
                "SELECT id, name FROM names WHERE name IN (SELECT value FROM json_each(?))", (names,)
            )
        }

    # ----------------------------------------------------------------- lookups

    def get_symbol(self, conn, uuid, addr):
        """(name_id, name, start, end) of the symbol covering addr, or None."""
        row = conn.execute(SYMBOL_AT_SQL, {"uuid": uuid, "addr": addr}).fetchone()
        if row is None:
            return None
        start, size, code, name = row
        return *decode_name(code, start, name), start, start + size

    def get_symbols(self, conn, uuid):
        """[(name_id, name, start, end), ...] sorted by start."""
        return [
            (*decode_name(code, start, name), start, start + size)
            for start, size, code, name in conn.execute(SYMBOLS_SQL, (uuid,))
        ]

    def get_ipsw(self, conn, version, build, device):
        row = conn.execute(
            """SELECT i.id, i.name, i.version, i.build, i.platform FROM ipsws i
               JOIN ipsw_devices d ON d.ipsw_id = i.id
               WHERE i.version = ? AND i.build = ? AND d.device = ?""",
            (version, build, device),
        ).fetchone()
        if row is None:
            return None
        devices = [d for (d,) in conn.execute("SELECT device FROM ipsw_devices WHERE ipsw_id = ?", (row[0],))]
        return ipsw_json(row, devices)

    def get_macho(self, conn, uuid):
        row = conn.execute("SELECT uuid, path, text_start, text_end FROM machos WHERE uuid = ?", (uuid,)).fetchone()
        return None if row is None else macho_json(row)

    def get_dsc(self, conn, uuid):
        row = conn.execute("SELECT uuid, shared_region_start FROM dyld_shared_caches WHERE uuid = ?", (uuid,)).fetchone()
        return None if row is None else {"uuid": row[0], "shared_region_start": row[1]}

    def get_dsc_image(self, conn, dsc_uuid, addr):
        """The dylib of a shared cache whose __TEXT contains addr."""
        row = conn.execute(
            """SELECT m.uuid, m.path, m.text_start, m.text_end FROM machos m
               JOIN dsc_images di ON di.macho_uuid = m.uuid
               WHERE di.dsc_uuid = ? AND m.text_start <= ? AND ? < m.text_end LIMIT 1""",
            (dsc_uuid, addr, addr),
        ).fetchone()
        return None if row is None else macho_json(row)

    def stats(self, conn):
        files = [self.path, self.path + "-wal"]
        out = {
            "db": self.path,
            "size_bytes": sum(os.path.getsize(f) for f in files if os.path.exists(f)),
            "tables": {},
        }
        tables = [t for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        try:  # per-table bytes (tables + their indexes), when sqlite has dbstat compiled in
            sizes = dict(conn.execute(
                """SELECT COALESCE(m.tbl_name, s.name), SUM(s.pgsize) FROM dbstat s
                   LEFT JOIN sqlite_master m ON m.name = s.name GROUP BY 1"""
            ))
        except sqlite3.OperationalError:
            sizes = {}
        for t in tables:
            (rows,) = conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()
            out["tables"][t] = {"rows": rows, "bytes": sizes.get(t)}
        return out


# --------------------------------------------------------------------------
# JSON shapes, matching how ipswd serializes its Go models
# (field names are what the `ipsw symbolicate --server` client decodes).
# --------------------------------------------------------------------------


def ipsw_json(row, devices):
    ipsw_id, name, version, build, platform = row
    return {
        "id": ipsw_id,
        "name": name,
        "version": version,
        "buildid": build,
        "platform": platform,
        "devices": [{"name": d} for d in devices],
    }


def macho_json(row):
    uuid, path, text_start, text_end = row
    return {
        "uuid": uuid,
        "PathID": 0,
        "Path": {"id": 0, "path": path},
        "text_start": text_start,
        "text_end": text_end,
        "Symbols": None,
    }


def symbol_json(name_id, name, start, end):
    return {
        "ID": 0,
        "NameID": name_id,
        "Name": {"ID": name_id, "name": name},
        "start": start,
        "end": end,
    }
