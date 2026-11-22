from pathlib import Path
from typing import Optional


class SymbolicatorException(Exception):
    """ Symbolicator related exception. """


class ScannerOutputError(SymbolicatorException):
    """ Raised when the input is not `ipsw symbols --json` output. """
    def __init__(self, reason: str, line_number: Optional[int] = None):
        super().__init__()
        self.reason = reason
        self.line_number = line_number

    def __str__(self) -> str:
        if self.line_number is None:
            return self.reason
        return f"line {self.line_number}: {self.reason}"


class IpswAlreadyLoadedError(SymbolicatorException):
    """ Raised when the IPSW is already in the database and loading it again was not asked for. """
    def __init__(self, name: str, sha1: str):
        super().__init__()
        self.name = name
        self.sha1 = sha1

    def __str__(self) -> str:
        return f"{self.name} ({self.sha1}) is already in the database"


class InvalidReportError(SymbolicatorException):
    """ Raised when the report is not an .ips report. """
    def __init__(self, reason: str):
        super().__init__()
        self.reason = reason

    def __str__(self) -> str:
        return f"not an .ips report: {self.reason}"


class IpswNotInstalledError(SymbolicatorException):
    """ Raised when the ipsw tool is not on the system. """


class NotAnIpswError(SymbolicatorException):
    """ Raised when the file to scan is not an .ipsw. """
    def __init__(self, path: Path):
        super().__init__()
        self.path = path


class ServerUnreachableError(SymbolicatorException):
    """ Raised when the server cannot be reached. """
    def __init__(self, server: str, reason: str):
        super().__init__()
        self.server = server
        self.reason = reason


class ServerError(SymbolicatorException):
    """ Raised when the server answers with an error. """
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__()
        self.message = message
        self.status_code = status_code
