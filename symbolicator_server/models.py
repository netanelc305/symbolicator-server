import dataclasses
from dataclasses import dataclass, field
from typing import Any, NamedTuple, Optional

from typer import style

# Kernel addresses have bit 63 set; the scanner stores them with it cleared, but its func_ names keep it.
HIGH_BIT = 1 << 63
# What clients from before /capabilities check, so it stays as it is. Routes have their own versions since,
# next to each of them in server.py.
API_VERSION = 2


@dataclass
class Ipsw:
    """ A row of the ipsw table. """
    id: int
    sha1: str
    name: str
    version: str
    build: str
    platform: Optional[str]
    devices: list[str]


@dataclass
class Image:
    """ A row of the image table: one copy of a binary and where it sits. """
    id: int
    macho_id: int
    kind: str
    path: str
    text_start: int
    text_size: int
    dsc_uuid: Optional[str]
    cpu: Optional[str]
    arch: Optional[str]
    kernel_version: Optional[str]
    offset_base: Optional[int]

    @classmethod
    def from_row(cls, row: tuple) -> "Image":
        return cls(*row)

    def contains(self, address: int) -> bool:
        """ Whether the address is in this copy's __TEXT. """
        return self.text_start <= address < self.text_start + self.text_size


class SymbolMatch(NamedTuple):
    """ The function covering an address. """
    offset: int
    name: Optional[str]  # None for an unnamed function


@dataclass
class SymbolRecord:
    """ One function of the scanner's output. """
    # an IPSW has millions of these; slots keep each one small (dataclass(slots=True) needs 3.10)
    __slots__ = ("name", "start", "end")
    name: Optional[str]  # None for the scanner's func_<address> placeholders and empty names
    start: int
    end: int

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "SymbolRecord":
        name = record["name"]
        start = record["start"]
        # empty, or the scanner's func_<address> placeholder (kernel ones keep bit 63)
        if name in ("", f"func_{start:x}", f"func_{start + HIGH_BIT:x}"):
            name = None
        return cls(name, start, record["end"])

    @property
    def size(self) -> int:
        if self.end < self.start:
            return 0  # an inverted range covers nothing
        return self.end - self.start


@dataclass
class ImageRecord:
    """ One image of the scanner's output, with the functions listed after it. """
    uuid: str
    kind: str
    path: str
    text_start: int
    text_end: int
    dsc_uuid: Optional[str]
    cpu: Optional[str]
    arch: Optional[str]
    kernel_version: Optional[str]
    symbols: list[SymbolRecord] = field(default_factory=list)

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "ImageRecord":
        return cls(record["uuid"], record["kind"], record["path"], record["text_start"], record["text_end"],
                   record.get("dsc_uuid"), record.get("cpu"), record.get("arch"), record.get("kernel_version"))

    @property
    def text_size(self) -> int:
        return self.text_end - self.text_start


@dataclass
class ServerVersion:
    """ What the server runs: its package version, HTTP API version and database schema version. """
    version: str
    api: int
    schema: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerVersion":
        return cls(data["version"], data["api"], data["schema"])


@dataclass
class SharedCache:
    """ A stored dyld_shared_cache: its UUID and the address it is mapped at. """
    uuid: str
    shared_region_start: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SharedCache":
        return cls(data["uuid"], data["shared_region_start"])


@dataclass
class ImageInfo:
    """ One copy of a binary and its __TEXT. Kernel addresses go without bit 63, as stored. """
    uuid: str
    path: str
    text_start: int
    text_end: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImageInfo":
        return cls(data["uuid"], data["path"], data["text_start"], data["text_end"])


class FunctionSymbol(NamedTuple):
    """ A function of an image copy, at its addresses in that copy. name is None for an unnamed function. """
    start: int
    end: int
    name: Optional[str]


@dataclass
class IpswStats:
    """ A loaded IPSW, as the stats list it. """
    name: str
    version: str
    build: str
    devices: list[str]
    images: int


@dataclass
class DatabaseStats:
    """ What the database holds: its size, rows per table and the loaded IPSWs. Its str is the colored view. """
    path: str
    size_bytes: int
    rows: dict[str, int]
    ipsws: list[IpswStats]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DatabaseStats":
        ipsws = [IpswStats(**ipsw) for ipsw in data["ipsws"]]
        return cls(data["path"], data["size_bytes"], data["rows"], ipsws)

    def without_ipsws(self) -> "DatabaseStats":
        return dataclasses.replace(self, ipsws=[])

    def __str__(self) -> str:
        lines = [f"{style('database  ', dim=True)}{self.path}  ({self.size_bytes / 1e9:.2f} GB)"]
        width = max(len(table) for table in self.rows)  # pad to the longest table name
        for table, count in self.rows.items():
            lines.append(f"{style(f'{table:<{width}}', dim=True)}{count:>14,}")

        if self.ipsws:
            lines.append("")
        for ipsw in self.ipsws:
            lines.append(f"{style(ipsw.name, fg='cyan', bold=True)}  {ipsw.version} ({ipsw.build})  "
                         f"{', '.join(ipsw.devices)}{style(f'  {ipsw.images:,} images', dim=True)}")
        return "\n".join(lines)
