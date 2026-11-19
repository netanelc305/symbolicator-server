import dataclasses
import re
from dataclasses import dataclass, field

from symbolicator_server.ips_report import BinaryImage, Frame, IpsReport, PanicFrame
from symbolicator_server.models import HIGH_BIT, Image
from symbolicator_server.symbols_dao import SymbolsDao

KERNEL_SOURCES = ["T", "K", "U"]
SHARED_CACHE_SOURCE = "S"
ABSOLUTE_SOURCE = "A"
KERNEL_KINDS = ["kernel", "kext"]
KERNELCACHE_SLIDE = re.compile(r"KernelCache slide:\s*(0x[0-9a-fA-F]+)")
PANIC_LR = re.compile(r"lr: (0x[0-9a-fA-F]+)")


@dataclass
class ReportImage:
    """ One of the report's binary images, and what the database has for it. """
    uuid: str
    base: int
    source: str
    copies: list[Image] = field(default_factory=list)  # the stored images with this UUID
    kexts: list[Image] = field(default_factory=list)   # for a fileset kernelcache: its kexts' images
    shared_region_start: int | None = None             # for a shared cache
    missing: bool = False

    @classmethod
    def from_binary_image(cls, binary_image: BinaryImage) -> "ReportImage":
        return cls(binary_image.uuid, binary_image.base, binary_image.source)

    @property
    def is_kernel(self) -> bool:
        return self.source in KERNEL_SOURCES

    def address_of(self, offset: int) -> int | None:
        """ The address of an offset into this image, or None if the database cannot place it. """
        if self.source == ABSOLUTE_SOURCE:
            return offset
        if self.is_kernel:
            return self.base + offset  # the report gives unslid kernel bases
        if self.source == SHARED_CACHE_SOURCE:
            if self.shared_region_start is None:
                return None
            return self.shared_region_start + offset
        if len(self.copies) == 0:
            return None
        return self.copies[0].text_start + offset


class Symbolicator:
    """
    Symbolicates an .ips report (panic, stackshot, crash) against the database.

    Each frame in a report is an image index and an offset into that image. How the offset becomes
    an address depends on the image's source letter:

        T, K, U   kernel and kexts      address = image base + offset
        S         dyld_shared_cache     address = cache's shared_region_start + offset
        P, C      Mach-O or dylib       address = the scanned image's __TEXT start + offset
        A         absolute              address = offset, nothing to look up

    Every frame except a thread's first is a return address: the instruction after a call. When the
    call is the last instruction of a function (a call to panic(), which never returns), the return
    address is already the first byte of the next function. So return addresses are looked up at
    address - 1, like atos does. The "+ offset" shown is still measured from the real address.
    """

    def __init__(self, dao: SymbolsDao):
        self.dao = dao
        self.images: list[ReportImage] = []
        # Threads repeat the same frames hundreds of times (every waiting thread is in
        # thread_invoke), so each frame is symbolicated once per report.
        self._frame_cache: dict[tuple[int, int, bool], Frame] = {}

    def symbolicate(self, report: IpsReport) -> IpsReport:
        """ The same report with symbols: its frames, the panic string's backtrace, and the images it lacks. """
        self.images = [self._find_image(binary_image) for binary_image in report.binary_images]
        self._frame_cache = {}

        processes = []
        for process in report.processes:
            threads = []
            for thread in process.threads:
                threads.append(dataclasses.replace(thread,
                                                   kernel_frames=self._symbolicate_frames(thread.kernel_frames),
                                                   user_frames=self._symbolicate_frames(thread.user_frames)))
            processes.append(dataclasses.replace(process, threads=threads))

        panic_backtrace = []
        if report.panic_string:
            panic_backtrace = self._symbolicate_panic_backtrace(report.panic_string)

        missing_images = set()
        for image in self.images:
            if image.missing:
                missing_images.add(image.uuid)

        return dataclasses.replace(report, processes=processes, panic_backtrace=panic_backtrace,
                                   missing_images=sorted(missing_images))

    def _find_image(self, binary_image: BinaryImage) -> ReportImage:
        image = ReportImage.from_binary_image(binary_image)
        if image.source == ABSOLUTE_SOURCE:
            return image

        if image.source == SHARED_CACHE_SOURCE:
            image.shared_region_start = self.dao.get_shared_region_start(image.uuid)
            image.missing = image.shared_region_start is None
        else:
            image.copies = self.dao.get_images_by_uuid(image.uuid)
            image.missing = len(image.copies) == 0

        if image.is_kernel:
            # Some reports (stackshots) give kernel frames as offsets into the whole fileset
            # kernelcache. Its functions are in its kexts, so those are what frames are looked up in.
            image.kexts = self.dao.get_kernelcache_kexts(image.uuid)
        return image

    def _symbolicate_frames(self, frames: list[Frame]) -> list[Frame]:
        symbolicated = []
        for i, frame in enumerate(frames):
            if self._is_null_frame(frame):
                continue
            is_return_address = i > 0
            key = (frame.image_index, frame.image_offset, is_return_address)
            if key not in self._frame_cache:
                self._frame_cache[key] = self._symbolicate_frame(frame, is_return_address)
            symbolicated.append(self._frame_cache[key])
        return symbolicated

    def _is_null_frame(self, frame: Frame) -> bool:
        """
        True for a frame at address 0: the end of a stack, or a thread whose stack was not captured.

        Reports give it as offset 0 into the absolute image. It is not a real frame.
        """
        if frame.image_index < 0 or frame.image_index >= len(self.images):
            return False
        return self.images[frame.image_index].source == ABSOLUTE_SOURCE and frame.image_offset == 0

    def _symbolicate_frame(self, report_frame: Frame, is_return_address: bool) -> Frame:
        frame = dataclasses.replace(report_frame)
        if frame.image_index < 0 or frame.image_index >= len(self.images):
            return frame
        image = self.images[frame.image_index]

        frame.address = image.address_of(frame.image_offset)
        if frame.address is None or image.source == ABSOLUTE_SOURCE:
            return frame

        address = frame.address
        if image.is_kernel:
            address -= HIGH_BIT  # the database stores kernel addresses without bit 63
        lookup_address = address
        if is_return_address:
            lookup_address = address - 1

        copy = self._find_copy(image, lookup_address)
        if copy is None:
            return frame
        frame.image = copy.path
        self._add_symbol(frame, copy, address, lookup_address)
        return frame

    def _find_copy(self, image: ReportImage, address: int) -> Image | None:
        """ The stored copy of the image to look the address up in. """
        if image.source == SHARED_CACHE_SOURCE:
            return self.dao.find_dylib_in_cache(image.uuid, address)

        copy = find_image_containing(image.kexts, address)
        if copy is None:
            copy = find_image_containing(image.copies, address)
        if copy is None and len(image.copies) > 0:
            # A kext can be in two kernelcaches (release and research) at different addresses.
            copy = image.copies[0]
        return copy

    def _symbolicate_panic_backtrace(self, panic_string: str) -> list[PanicFrame]:
        """
        The panicked thread's backtrace in the panic string: its "lr: 0x..." lines.

        Subtracting the "KernelCache slide" from the panic string gives the addresses the database has.
        """
        match = KERNELCACHE_SLIDE.search(panic_string)
        if match is None:
            return []
        slide = int(match.group(1), 16)

        kernel_copies = []
        for image in self.images:
            if image.is_kernel:
                kernel_copies.extend(image.copies)
                kernel_copies.extend(image.kexts)

        backtrace = []
        for match in PANIC_LR.finditer(panic_string):
            slid_address = int(match.group(1), 16)
            frame = PanicFrame(slid_address, slid_address - slide)
            backtrace.append(frame)

            address = frame.address - HIGH_BIT
            lookup_address = address - 1  # every lr is a return address
            copy = find_image_containing(kernel_copies, lookup_address)
            if copy is None:
                continue
            frame.image = copy.path
            self._add_symbol(frame, copy, address, lookup_address)
        return backtrace

    def _add_symbol(self, frame: Frame | PanicFrame, copy: Image, address: int, lookup_address: int) -> None:
        """ Fill in the frame's symbol and offset from the given image copy. """
        if copy.offset_base is None:
            return  # this copy could not be lined up with its UUID's symbols
        match = self.dao.find_symbol(copy.macho_id, lookup_address - copy.offset_base)
        if match is None:
            return
        start = copy.offset_base + match.offset  # the function's address in this copy
        if match.name is not None:
            frame.symbol = match.name
        elif copy.kind in KERNEL_KINDS:
            frame.symbol = f"func_{start + HIGH_BIT:x}"  # kernel addresses are shown with bit 63
        else:
            frame.symbol = f"func_{start:x}"
        frame.offset = address - start


def find_image_containing(images: list[Image], address: int) -> Image | None:
    """ The first image whose __TEXT contains address. """
    for image in images:
        if image.contains(address):
            return image
    return None
