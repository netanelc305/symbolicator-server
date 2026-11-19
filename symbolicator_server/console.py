import logging

from rich import get_console
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn

LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_cli_logging() -> None:
    """ Log the CLI's messages to stderr, so the printed output stays clean. """
    handler = RichHandler(console=Console(stderr=True), show_time=False, show_path=False)
    logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[handler])


def setup_server_logging(verbose: bool = False) -> None:
    """ Log the server's messages, uvicorn's too, with time and logger name. """
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    handler = RichHandler(console=Console(stderr=True), show_path=False, log_time_format=LOG_TIME_FORMAT)
    logging.basicConfig(level=level, format="%(name)s: %(message)s", handlers=[handler], force=True)


class ScanProgress:
    """ The client's lines while a scan runs, one per stage: spinner (a check once done), time, what was done. """

    def __init__(self, progress: Progress, upload_task: TaskID):
        self.progress = progress
        self.upload_task = upload_task
        self.load_task: TaskID | None = None

    @classmethod
    def start(cls) -> "ScanProgress":
        progress = Progress(SpinnerColumn(finished_text="[green]✓"), TimeElapsedColumn(),
                            TextColumn("{task.description}"), console=get_console())
        progress.start()
        return cls(progress, progress.add_task("Uploaded:", total=1))

    def uploaded(self, sent: int, size: int) -> None:
        self.progress.update(self.upload_task, description=f"Uploaded: {sent / 1e9:.1f} / {size / 1e9:.1f} GB")

    def loaded(self, counts: dict[str, int]) -> None:
        """ Show the counts so far; the first call ends the upload stage. """
        if self.load_task is None:
            self.progress.update(self.upload_task, completed=1)
            self.load_task = self.progress.add_task("", total=1)
        self.progress.update(self.load_task, description=f"Loaded: {counts['image']:,} images, "
                                                         f"{counts['symbol']:,} symbols")

    def done(self, counts: dict[str, int]) -> None:
        self.loaded(counts)
        if self.load_task is not None:
            self.progress.update(self.load_task, completed=1)

    def stop(self) -> None:
        self.progress.stop()

    def __enter__(self) -> "ScanProgress":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
