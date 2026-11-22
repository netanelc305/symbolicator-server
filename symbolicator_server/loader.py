import json
import logging
from collections.abc import Iterable, Iterator
from typing import Any, Optional

from symbolicator_server.exceptions import IpswAlreadyLoadedError, ScannerOutputError
from symbolicator_server.models import ImageRecord, Ipsw, SymbolRecord
from symbolicator_server.symbols_dao import SymbolsDao

OFFSET_BASE_SAMPLE_SIZE = 64
PROGRESS_EVERY_IMAGES = 100
LOG_EVERY_IMAGES = 1000

logger = logging.getLogger(__name__)


class IpswLoader:
    """
    Loads one `ipsw symbols --json` output into the database.

    Does not commit: the caller commits once it knows the output is complete. A real name replaces
    an unnamed one, and names the UUID already has are kept, unless the new name comes from a file
    on disk.
    """

    def __init__(self, dao: SymbolsDao, force: bool = False):
        """
        Parameters
        ----------
        dao : SymbolsDao
            The database to load into.
        force : bool
            Load the IPSW again if it is already in the database.
        """
        self.dao = dao
        self.force = force
        self.counts = {"ipsw": 0, "dsc": 0, "image": 0, "symbol": 0}
        self.ipsw: Optional[Ipsw] = None
        self._image: Optional[ImageRecord] = None
        # The scanner writes a kernelcache's record followed by its kexts' records: that order is the
        # only place it says which kexts are in which kernelcache.
        self._kernelcache_id: Optional[int] = None
        self._record_loaders = {
            "dsc": self._load_dsc_record,
            "image": self._load_image_record,
            "symbol": self._load_symbol_record,
        }

    def load(self, lines: Iterable[str]) -> Iterator[dict[str, int]]:
        """
        Load the scanner's output lines.

        Yields how many records of each type were read so far, every PROGRESS_EVERY_IMAGES images.
        The load is done when the iteration ends; self.counts then has the totals.
        """
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            record = self._parse_line(line, line_number)
            record_type = record["type"]
            if record_type not in self.counts:
                # other record types (comparison facts) are not stored
                continue
            self.counts[record_type] += 1

            if record_type == "ipsw":
                self.ipsw = self._load_ipsw_record(record)
                continue
            if self.ipsw is None:
                raise ScannerOutputError(f"{record_type} record before the ipsw record", line_number)
            self._record_loaders[record_type](self.ipsw, record, line_number)

            if record_type == "image" and self.counts["image"] % PROGRESS_EVERY_IMAGES == 0:
                if self.counts["image"] % LOG_EVERY_IMAGES == 0:
                    logger.info(f"{self.ipsw.name}: loading, {self.counts['image']:,} images, "
                                f"{self.counts['symbol']:,} symbols so far")
                yield dict(self.counts)

        if self.ipsw is None:
            raise ScannerOutputError("no ipsw record: empty, or not `ipsw symbols --json` output")
        if self._image is not None:
            self._save_image(self.ipsw, self._image)
        logger.info(f"Read {self.ipsw.name}: {self.counts['image']} images, {self.counts['symbol']} symbols")
        yield dict(self.counts)

    @staticmethod
    def _parse_line(line: str, line_number: int) -> dict[str, Any]:
        try:
            record = json.loads(line)
        except ValueError:
            raise ScannerOutputError("not an `ipsw symbols --json` record", line_number) from None
        if not isinstance(record, dict) or "type" not in record:
            raise ScannerOutputError("not an `ipsw symbols --json` record", line_number)
        return record

    def _load_ipsw_record(self, record: dict[str, Any]) -> Ipsw:
        existing = self.dao.get_ipsw_by_sha1(record["id"])
        if existing is not None:
            if not self.force:
                raise IpswAlreadyLoadedError(record["name"], record["id"])
            logger.info(f"Removing {existing.name} to load it again")
            self.dao.delete_ipsw(existing.id)

        ipsw = self.dao.add_ipsw(record["id"], record["name"], record["version"], record["build"],
                                 record.get("platform"), record.get("devices", []))
        logger.info(f"Loading {ipsw.name} ({ipsw.version} {ipsw.build})")
        return ipsw

    def _load_dsc_record(self, ipsw: Ipsw, record: dict[str, Any], line_number: int) -> None:
        self.dao.add_dsc(ipsw.id, record["uuid"], record["shared_region_start"])

    def _load_image_record(self, ipsw: Ipsw, record: dict[str, Any], line_number: int) -> None:
        if self._image is not None:
            self._save_image(ipsw, self._image)
        self._image = ImageRecord.from_dict(record)

    def _load_symbol_record(self, ipsw: Ipsw, record: dict[str, Any], line_number: int) -> None:
        if self._image is None or record["image_uuid"] != self._image.uuid:
            raise ScannerOutputError(f"symbol of {record['image_uuid']} outside its image's records", line_number)
        self._image.symbols.append(SymbolRecord.from_dict(record))

    def _save_image(self, ipsw: Ipsw, record: ImageRecord) -> None:
        """ Link this IPSW to the image (creating it if new) and add the symbols to its UUID's. """
        macho_id = self.dao.get_macho_id(record.uuid)
        if macho_id is None:
            macho_id = self.dao.add_macho(record.uuid)

        stored = self.dao.get_symbols(macho_id)
        image = self.dao.find_image(macho_id, record)
        if image is None:
            image = self.dao.add_image(macho_id, record, find_offset_base(stored, record))
            if image.offset_base is None:
                logger.warning(f"{record.uuid} {image.path}: its functions do not line up with the stored ones, "
                               f"its symbols are not used")
            elif image.offset_base != image.text_start:
                logger.info(f"{record.uuid} {image.path}: lined up at base {image.offset_base:#x} "
                            f"(text_start {image.text_start:#x})")
        self.dao.link_ipsw_image(ipsw.id, image.id)

        if record.kind == "kernel":
            self._kernelcache_id = macho_id
        elif record.kind == "kext":
            if self._kernelcache_id is not None:
                self.dao.link_kernelcache_kext(self._kernelcache_id, image.id)
        else:
            self._kernelcache_id = None

        if image.offset_base is not None:
            self._merge_symbols(macho_id, image.offset_base, record, stored)

    def _merge_symbols(self, macho_id: int, offset_base: int, record: ImageRecord,
                       stored: dict[int, Optional[int]]) -> None:
        """ Add the new functions of this copy and the names the stored ones are missing. """
        names = set()
        for symbol in record.symbols:
            if symbol.name is not None:
                names.add(symbol.name)
        name_ids = self.dao.get_name_ids(names)

        new_rows = []
        named_rows = []
        for symbol in record.symbols:
            offset = symbol.start - offset_base
            name_id = None
            if symbol.name is not None:
                name_id = name_ids[symbol.name]

            if offset not in stored:
                new_rows.append((macho_id, offset, symbol.size, name_id))
                stored[offset] = name_id
                continue
            stored_name_id = stored[offset]
            if name_id is None or stored_name_id == name_id:
                continue

            if stored_name_id is None:
                logger.debug(f"{record.uuid} {record.path} +{offset:#x}: func_ placeholder -> {symbol.name}")
            elif record.kind == "macho":
                # A file on disk has the linker's own names. A kernelcache kext is stripped and
                # named from kernel signatures, which sometimes land on the wrong function.
                logger.debug(f"{record.uuid} {record.path} +{offset:#x}: replaced "
                             f"{self.dao.get_name_text(stored_name_id)} with {symbol.name} (from the file on disk)")
            else:
                logger.debug(f"{record.uuid} {record.path} +{offset:#x}: kept "
                             f"{self.dao.get_name_text(stored_name_id)}, ignored {symbol.name}")
                continue
            named_rows.append((name_id, macho_id, offset))
            stored[offset] = name_id

        self.dao.add_symbols(new_rows)
        self.dao.set_symbol_names(named_rows)
        if len(named_rows) > 0:
            logger.info(f"{record.uuid} {record.path}: named or renamed {len(named_rows)} functions, "
                        f"added {len(new_rows)} functions")


def find_offset_base(stored: dict[int, Optional[int]], record: ImageRecord) -> Optional[int]:
    """
    The address of offset 0 in this copy, so that its functions line up with the stored ones.

    All copies of a UUID start their functions at the same offsets. For most copies, offset 0 is
    text_start. When it is not (a standalone .kext), the right base is found by trying the bases
    that put one of this copy's first functions on a stored function, and keeping the one where
    most functions line up. Returns None if no base lines most of them up.
    """
    if len(stored) == 0 or len(record.symbols) == 0:
        return record.text_start  # the first copy of this UUID: it defines the offsets

    starts = sorted(set(symbol.start for symbol in record.symbols))
    # enough functions, spread over the image, to tell a right base from a wrong one
    step = max(1, len(starts) // OFFSET_BASE_SAMPLE_SIZE)
    sample = starts[::step][:OFFSET_BASE_SAMPLE_SIZE]

    if count_lined_up(stored, sample, record.text_start) * 2 >= len(sample):
        return record.text_start

    best_base = None
    best_count = 0
    for start in starts[:3]:
        for offset in stored:
            base = start - offset
            count = count_lined_up(stored, sample, base)
            if count > best_count:
                best_base = base
                best_count = count
    if best_count >= 3 and best_count * 2 > len(sample):
        return best_base
    return None


def count_lined_up(stored: dict[int, Optional[int]], starts: list[int], base: int) -> int:
    """ How many of the starts land on a stored function when offset 0 is at base. """
    count = 0
    for start in starts:
        if start - base in stored:
            count += 1
    return count
