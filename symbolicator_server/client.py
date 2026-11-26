import json
import urllib.error
import urllib.parse
import urllib.request
from functools import cached_property
from http.client import HTTPResponse
from pathlib import Path
from typing import BinaryIO, Optional, Union

from symbolicator_server.console import ScanProgress
from symbolicator_server.exceptions import IncompatibleServerError, ServerError, ServerUnreachableError
from symbolicator_server.models import DatabaseStats, FunctionSymbol, ImageInfo, Kernelcache, ServerVersion, SharedCache

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

    @classmethod
    def connect(cls, server: str = DEFAULT_SERVER) -> "SymbolicatorClient":
        """ A client for the server, once it is known to be there and to tell its capabilities. """
        client = cls(server)
        client.capabilities
        return client

    @cached_property
    def capabilities(self) -> dict[str, str]:
        """ The MAJOR.MINOR version of each route the server speaks. """
        capabilities = self._get_json("/capabilities")
        if capabilities is None:
            # servers from before capabilities
            raise IncompatibleServerError(self.server, "/capabilities", None, "1.0")
        return capabilities

    def version(self) -> ServerVersion:
        """ The server's package, API and database schema versions. """
        self._require("/version", "1.0")
        return ServerVersion.from_dict(self._get_json("/version"))

    def scan(self, ipsw_path: Path, force: bool, status: ScanProgress) -> dict[str, int]:
        """ Send the IPSW to the server, then follow its stages; returns how many records it loaded. """
        self._require("/scan", "1.0")
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
        self._require("/symbolicate", "1.0")
        with self._post("/symbolicate", report_path.read_bytes()) as response:
            return json.load(response)

    def stats(self) -> DatabaseStats:
        """ What the server's database holds. """
        self._require("/stats", "1.0")
        with self._open(urllib.request.Request(f"{self.server}/stats")) as response:
            return DatabaseStats.from_dict(json.load(response))

    def find_dscs(self, device: str, build: str) -> list[SharedCache]:
        """ The shared caches of a device's build (none if the server has no IPSW of it). """
        self._require("/dsc", "1.0")
        query = urllib.parse.urlencode({"device": device, "build": build})
        return [SharedCache.from_dict(dsc) for dsc in self._get_json(f"/dsc?{query}")]

    def dsc_images(self, uuid: str) -> Optional[list[ImageInfo]]:
        """ The images of a shared cache; None if the server does not have it. """
        self._require("/dsc/{uuid}/images", "1.0")
        images = self._get_json(f"/dsc/{urllib.parse.quote(uuid)}/images")
        return None if images is None else [ImageInfo.from_dict(image) for image in images]

    def find_kernelcaches(self, device: str, build: str) -> list[Kernelcache]:
        """ The kernelcaches of a device's build (none if the server has no IPSW of it). """
        self._require("/kernelcache", "1.0")
        query = urllib.parse.urlencode({"device": device, "build": build})
        return [Kernelcache.from_dict(kernelcache) for kernelcache in self._get_json(f"/kernelcache?{query}")]

    def kernelcache_images(self, uuid: str) -> Optional[list[ImageInfo]]:
        """ The kexts of a kernelcache, the kernel among them; None if the server does not have it. """
        self._require("/kernelcache/{uuid}/images", "1.0")
        images = self._get_json(f"/kernelcache/{urllib.parse.quote(uuid)}/images")
        return None if images is None else [ImageInfo.from_dict(image) for image in images]

    def image_symbols(self, uuid: str, dsc: Optional[str] = None,
                      kernelcache: Optional[str] = None) -> Optional[list[FunctionSymbol]]:
        """
        The functions of an image, at the addresses of its copy in the given shared cache or kernelcache;
        None if the server has no such copy. Kernel addresses go without bit 63.
        """
        self._require("/images/{uuid}/symbols", "1.0")
        query = {key: value for key, value in (("dsc", dsc), ("kernelcache", kernelcache)) if value is not None}
        path = f"/images/{urllib.parse.quote(uuid)}/symbols"
        if query:
            path += f"?{urllib.parse.urlencode(query)}"
        symbols = self._get_json(path)
        return None if symbols is None else [FunctionSymbol(*symbol) for symbol in symbols]

    def find_functions(self, images: dict[str, list[int]], dsc: Optional[str] = None,
                       kernelcache: Optional[str] = None) -> dict[str, list[Optional[FunctionSymbol]]]:
        """
        The function covering each of the given addresses, by the UUID of the image they are in and in the
        order given; None for an address no function covers. The addresses are those of the copy of each
        image in the given shared cache or kernelcache, as image_symbols() gives them. An image the server
        has no such copy of is left out.
        """
        self._require("/functions", "1.0")
        query = {key: value for key, value in (("images", images), ("dsc", dsc), ("kernelcache", kernelcache))
                 if value is not None}
        request = urllib.request.Request(f"{self.server}/functions", data=json.dumps(query).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        with self._open(request) as response:
            return {uuid: [None if function is None else FunctionSymbol(*function) for function in functions]
                    for uuid, functions in json.load(response).items()}

    def _require(self, route: str, version: str) -> None:
        """
        Raise unless the server speaks the given version of the route, the one its caller is written for:
        the same major, and that minor or a later one.
        """
        server_api = self.capabilities.get(route)
        if server_api is not None:
            major, minor = map(int, version.split("."))
            server_major, server_minor = map(int, server_api.split("."))
            if server_major == major and server_minor >= minor:
                return
        raise IncompatibleServerError(self.server, route, server_api, version)

    def _get_json(self, path: str):
        """ The JSON a GET answers; None on a 404. """
        try:
            response = self._open(urllib.request.Request(f"{self.server}{path}"))
        except ServerError as e:
            if e.status_code == 404:
                return None
            raise e
        with response:
            return json.load(response)

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
