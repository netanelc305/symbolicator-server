import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from operator import attrgetter
from typing import Any, Optional

from typer import style

from symbolicator_server.exceptions import InvalidReportError

PANICKED_TASK = re.compile(r"Panicked task .*?pid (\d+):")
CAMEL_CASE_WORD = re.compile(r"(?<=[a-z])(?=[A-Z])")
REPORT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f %z"
TITLE_TIMESTAMP_FORMAT = "%d%b%Y %H:%M:%S"
BUG_TYPES = {"210": "Panic", "288": "Stackshot", "309": "Crash"}


@dataclass
class BinaryImage:
    """ One entry of the report's binaryImages. """
    uuid: str
    base: int
    source: str  # where the report took the image from: T, K, U kernel; S shared cache; P, C Mach-O; A absolute

    @classmethod
    def from_list(cls, raw_image: list) -> "BinaryImage":
        """ Create from the report's [uuid, base, source]. """
        return cls(raw_image[0].upper(), raw_image[1], raw_image[2])


@dataclass
class Frame:
    """ A stack frame: an offset into one of the report's binary images, then what symbolication found. """
    image_index: int
    image_offset: int
    image: Optional[str] = None
    address: Optional[int] = None
    symbol: Optional[str] = None
    offset: Optional[int] = None


@dataclass
class PanicFrame:
    """ A frame of the panic string's backtrace. Its address is slid: where the kernel was in memory. """
    slid_address: int
    address: int
    image: Optional[str] = None
    symbol: Optional[str] = None
    offset: Optional[int] = None


@dataclass
class ReportThread:
    id: int
    name: Optional[str]
    state: Optional[list[str]]
    base_priority: Optional[int]
    sched_priority: Optional[int]
    user_usec: Optional[int]
    system_usec: Optional[int]
    kernel_frames: list[Frame]
    user_frames: list[Frame]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportThread":
        kernel_frames = [Frame(**frame) for frame in data["kernel_frames"]]
        user_frames = [Frame(**frame) for frame in data["user_frames"]]
        return cls(data["id"], data["name"], data["state"], data["base_priority"], data["sched_priority"],
                   data["user_usec"], data["system_usec"], kernel_frames, user_frames)

    @classmethod
    def from_ips(cls, thread_id: str, thread: dict[str, Any]) -> "ReportThread":
        """ Create from a thread of the .ips payload's threadById. """
        kernel_frames = [Frame(raw_frame[0], raw_frame[1]) for raw_frame in thread.get("kernelFrames", [])]
        user_frames = [Frame(raw_frame[0], raw_frame[1]) for raw_frame in thread.get("userFrames", [])]
        return cls(int(thread.get("id", thread_id)), thread.get("name"), thread.get("state"),
                   thread.get("basePriority"), thread.get("schedPriority"), thread.get("user_usec"),
                   thread.get("system_usec"), kernel_frames, user_frames)


@dataclass
class ReportProcess:
    pid: int
    name: Optional[str]
    threads: list[ReportThread]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportProcess":
        threads = [ReportThread.from_dict(thread) for thread in data["threads"]]
        return cls(data["pid"], data["name"], threads)


@dataclass
class IpsReport:
    """
    An .ips report (panic, stackshot, crash). format() is its colored terminal view.

    parse() reads the report as it is; Symbolicator.symbolicate() returns a copy with the frames' images,
    addresses and symbols filled in, the panic string's backtrace, and the images the database lacks.
    """
    bug_type: Optional[str]
    timestamp: Optional[str]
    os_version: Optional[str]
    product: Optional[str]
    panic_string: Optional[str]
    reason: Optional[str]
    memory_status: dict[str, Any]
    notes: list[str]
    binary_images: list[BinaryImage]
    processes: list[ReportProcess]
    panic_backtrace: list[PanicFrame] = field(default_factory=list)
    missing_images: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, text: str) -> "IpsReport":
        """ Read an .ips report: a JSON header line, then a JSON payload. """
        first_line, _, rest = text.partition("\n")
        try:
            header = json.loads(first_line)
            payload = json.loads(rest)
        except json.JSONDecodeError as e:
            raise InvalidReportError(str(e)) from None
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise InvalidReportError("its header or payload is not a JSON object")

        binary_images = [BinaryImage.from_list(raw_image) for raw_image in payload.get("binaryImages", [])]
        processes = []
        for pid, process in payload.get("processByPid", {}).items():
            threads = []
            for thread_id, thread in process.get("threadById", {}).items():
                threads.append(ReportThread.from_ips(thread_id, thread))
            processes.append(ReportProcess(int(pid), process.get("procname"), threads))

        return cls(bug_type=header.get("bug_type"),
                   timestamp=header.get("timestamp"),
                   os_version=header.get("os_version"),
                   product=payload.get("product"),
                   panic_string=payload.get("panicString"),
                   reason=payload.get("reason"),
                   memory_status=payload.get("memoryStatus", {}),
                   notes=payload.get("notes", []),
                   binary_images=binary_images,
                   processes=processes)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IpsReport":
        """ Create from the server's JSON of a report. """
        binary_images = [BinaryImage(**image) for image in data["binary_images"]]
        processes = [ReportProcess.from_dict(process) for process in data["processes"]]
        panic_backtrace = [PanicFrame(**frame) for frame in data["panic_backtrace"]]
        return cls(data["bug_type"], data["timestamp"], data["os_version"], data["product"], data["panic_string"],
                   data["reason"], data["memory_status"], data["notes"], binary_images, processes, panic_backtrace,
                   data["missing_images"])

    @property
    def panicked_pid(self) -> Optional[int]:
        """ The pid in the panic string's "Panicked task ... pid 0: kernel_task" line, or None. """
        if not self.panic_string:
            return None
        match = PANICKED_TASK.search(self.panic_string)
        if match is None:
            return None
        return int(match.group(1))

    def format(self, proc: Optional[str] = None, all_procs: bool = False) -> str:
        """
        The colored terminal view, symbolicated or not: title, panic string and its backtrace, memory status,
        the processes by pid and their threads by id, then the notes.

        Shows only the panicked process by default, the process named proc, or every one with all_procs.
        """
        lines = [style(self._title(), bold=True)]
        if self.panic_string:
            lines.append("")
            panic_lines = self.panic_string.rstrip().split("\n")
            lines.append(style(panic_lines[0], fg="red", bold=True))
            lines.extend(panic_lines[1:])
        elif self.reason:
            lines.append(style(f"Reason: {self.reason}", fg="red", bold=True))

        if self.panic_backtrace:
            lines.append("")
            lines.append(style("Panicked Thread Backtrace (from the panic string):", bold=True))
            lines.extend(self._panic_backtrace_lines())

        if self.memory_status:
            lines.append("")
            lines.append(style("Memory Status:", bold=True))
            lines.extend(dict_lines(self.memory_status, "  "))

        panicked_pid = self.panicked_pid
        for process in sorted(self._processes_to_show(proc, all_procs), key=attrgetter("pid")):
            lines.append("")
            title = style("Process: ", dim=True) + style(f"{process.name} [{process.pid}]", fg="cyan", bold=True)
            if process.pid == panicked_pid:
                title += style(" (Panicked)", fg="red", bold=True)
            lines.append(title)
            for thread in sorted(process.threads, key=attrgetter("id")):
                if thread.kernel_frames or thread.user_frames:
                    lines.extend(self._thread_lines(thread))

        if self.notes:
            lines.append("")
            lines.append(style("NOTES:", bold=True))
            for note in self.notes:
                lines.append(f"    - {note}")
        return "\n".join(lines)

    def _title(self) -> str:
        """ Like `[25Sep2026 20:10:09] - Stackshot - iPhone13,4 iPhone OS 26.5.2 (23F84)`. """
        timestamp = self.timestamp
        try:
            report_time = datetime.strptime(self.timestamp or "", REPORT_TIMESTAMP_FORMAT)
            timestamp = report_time.strftime(TITLE_TIMESTAMP_FORMAT)
        except ValueError:
            pass
        kind = BUG_TYPES.get(self.bug_type or "", f"bug_type {self.bug_type}")
        return f"[{timestamp}] - {kind} - {self.product} {self.os_version}"

    def _processes_to_show(self, proc: Optional[str], all_procs: bool) -> list[ReportProcess]:
        panicked_pid = self.panicked_pid
        processes = []
        for process in self.processes:
            if proc is not None:
                if process.name == proc:
                    processes.append(process)
            elif all_procs or panicked_pid is None or process.pid == panicked_pid:
                processes.append(process)
        return processes

    def _panic_backtrace_lines(self) -> list[str]:
        columns = []
        for frame in self.panic_backtrace:
            columns.append((image_name(frame.image), f"{frame.address:#x}", frame.symbol, frame.offset))
        return frame_lines(columns)

    def _thread_lines(self, thread: ReportThread) -> list[str]:
        title = style("  Thread: ", dim=True) + str(thread.id)
        if thread.name:
            title += style(f"  {thread.name}", bold=True)
        lines = [title]
        if thread.state:
            lines.append(field_line("State", ", ".join(thread.state)))
        if thread.base_priority is not None:
            lines.append(field_line("Base Priority", str(thread.base_priority)))
        if thread.sched_priority is not None:
            lines.append(field_line("Sched Priority", str(thread.sched_priority)))
        if thread.user_usec is not None:
            lines.append(field_line("User Time", f"{thread.user_usec} usec"))
        if thread.system_usec is not None:
            lines.append(field_line("System Time", f"{thread.system_usec} usec"))

        if thread.kernel_frames:
            lines.append(style("    Kernel Frames:", dim=True))
            lines.extend(frame_lines(self._frame_columns(thread.kernel_frames)))
        if thread.user_frames:
            lines.append(style("    User Frames:", dim=True))
            lines.extend(frame_lines(self._frame_columns(thread.user_frames)))
        return lines

    def _frame_columns(self, frames: list[Frame]) -> list[tuple[str, str, Optional[str], Optional[int]]]:
        """ (image, address, symbol, offset) of each frame. """
        columns = []
        for frame in frames:
            # not symbolicated: the offset into the report's binary image
            address = f"+{frame.image_offset:#x}"
            if frame.address is not None:
                address = f"{frame.address:#x}"
            columns.append((self._frame_image(frame), address, frame.symbol, frame.offset))
        return columns

    def _frame_image(self, frame: Frame) -> str:
        """ The frame's image name, or else its binary image's UUID. """
        if frame.image:
            return image_name(frame.image)
        if 0 <= frame.image_index < len(self.binary_images):
            return self.binary_images[frame.image_index].uuid
        return "???"

    def __str__(self) -> str:
        return self.format()


def image_name(path: Optional[str]) -> str:
    if not path:
        return "???"
    return path.split("/")[-1]


def field_line(label: str, value: str) -> str:
    return style(f"    {label + ':':<16}", dim=True) + value


def frame_lines(columns: list[tuple[str, str, Optional[str], Optional[int]]]) -> list[str]:
    """ One line per frame: index, image, address, symbol + offset, the columns as wide as their longest entry. """
    image_width = 0
    address_width = 0
    for image, address, _, _ in columns:
        image_width = max(image_width, len(image))
        address_width = max(address_width, len(address))

    lines = []
    for i, (image, address, symbol, offset) in enumerate(columns):
        if symbol is None:
            symbol_text = style("???", fg="red", dim=True)
        elif symbol.startswith("func_"):
            symbol_text = style(symbol_with_offset(symbol, offset), fg="yellow")
        else:
            symbol_text = style(symbol_with_offset(symbol, offset), fg="green")
        image_column = style(f"{image:<{image_width}}", fg="blue")
        address_column = style(f"{address:<{address_width}}", fg="magenta")
        lines.append(f"      {i:02d}: {image_column}  {address_column}  {symbol_text}")
    return lines


def symbol_with_offset(symbol: str, offset: Optional[int]) -> str:
    if offset:
        return f"{symbol} + {offset}"
    return symbol


def dict_lines(data: dict[str, Any], indent: str) -> list[str]:
    """ A nested dict as indented "Some Key: value" lines, keys sorted, camelCase keys split into words. """
    lines = []
    for key in sorted(data):
        words = CAMEL_CASE_WORD.sub(" ", key)
        label = words[0].upper() + words[1:]
        value = data[key]
        if isinstance(value, dict):
            lines.append(f"{indent}{label}:")
            lines.extend(dict_lines(value, indent + "  "))
        elif isinstance(value, bool):
            lines.append(f"{indent}{label}: {str(value).lower()}")
        else:
            lines.append(f"{indent}{label}: {value}")
    return lines
