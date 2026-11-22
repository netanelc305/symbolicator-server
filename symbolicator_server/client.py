import json
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import BinaryIO, Optional, Union

from symbolicator_server.console import ScanProgress
from symbolicator_server.exceptions import ServerError, ServerUnreachableError
from symbolicator_server.models import DatabaseStats

DEFAULT_SERVER = "http://localhost:3993"


class UploadProgress:
    """ A file sent as a request body: urllib reads it piece by piece, and each read updates the upload line. """

    def __init__(self, f: BinaryIO, size: int, status: ScanProgress):
        self.f = f
        self.size = size
        self.status = status
        self.sent = 0

    def read(self, size: int = -1) -> bytes:
        data = self.f.read(size)
        self.sent += len(data)
        self.status.uploaded(self.sent, self.size)
        return data


class SymbolicatorClient:
    """ Talks to a symbolicator server. """

    def __init__(self, server: str = DEFAULT_SERVER):
        self.server = server.rstrip("/")

    def scan(self, ipsw_path: Path, force: bool, status: ScanProgress) -> dict[str, int]:
        """ Send the IPSW to the server, then follow its stages; returns how many records it loaded. """
        query = {"name": ipsw_path.name}
        if force:
            query["force"] = "true"
        size = ipsw_path.stat().st_size
        with ipsw_path.open("rb") as f:
            body = UploadProgress(f, size, status)
            status.uploaded(0, size)
            with self._post(f"/scan?{urllib.parse.urlencode(query)}", body, size) as response:
                status.loaded({"image": 0, "symbol": 0})
                # one JSON line per stage as the server starts it, and per progress update while it loads
                for line in response:
                    message = json.loads(line)
                    if "progress" in message:
                        status.loaded(message["progress"])
                    elif "error" in message:
                        raise ServerError(message["error"])
                    elif "done" in message:
                        status.done(message["done"])
                        return message["done"]
        raise ServerError("the server stopped before the scan was done")

    def symbolicate(self, report_path: Path) -> dict:
        """ The symbolicated report, as the server's JSON. """
        with self._post("/symbolicate", report_path.read_bytes()) as response:
            return json.load(response)

    def stats(self) -> DatabaseStats:
        """ What the server's database holds. """
        with self._open(urllib.request.Request(f"{self.server}/stats")) as response:
            return DatabaseStats.from_dict(json.load(response))

    def _post(self, path: str, body: Union[bytes, UploadProgress], size: Optional[int] = None) -> HTTPResponse:
        headers = {}
        if size is not None:
            headers["Content-Length"] = str(size)  # urllib cannot tell a file's size by itself
        return self._open(urllib.request.Request(f"{self.server}{path}", data=body, method="POST", headers=headers))

    def _open(self, request: urllib.request.Request) -> HTTPResponse:
        try:
            return urllib.request.urlopen(request)
        except urllib.error.HTTPError as e:
            try:
                message = json.load(e)["error"]
            except (ValueError, KeyError):
                message = e.reason
            raise ServerError(message, e.code) from None
        except urllib.error.URLError as e:
            raise ServerUnreachableError(self.server, str(e.reason)) from None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} SERVER:{self.server}>"
