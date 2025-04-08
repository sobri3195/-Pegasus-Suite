"""
Type stub file to help Pylance with external module resolution.
"""

# colorama stubs
import typing

class Style:
    BRIGHT: str
    RESET_ALL: str
    DIM: str
    NORMAL: str

class Fore:
    RED: str
    GREEN: str
    YELLOW: str
    BLUE: str
    MAGENTA: str
    CYAN: str
    WHITE: str
    BLACK: str
    RESET: str

class Back:
    RED: str
    GREEN: str
    YELLOW: str
    BLUE: str
    MAGENTA: str
    CYAN: str
    WHITE: str
    BLACK: str
    RESET: str

def init(autoreset: bool = False) -> None: ...

# requests stubs
class Response:
    status_code: int
    text: str
    content: bytes
    
    def json(self) -> typing.Dict[str, typing.Any]: ...
    def raise_for_status(self) -> None: ...

def get(
    url: str, 
    params: typing.Optional[typing.Dict[str, typing.Any]] = None,
    headers: typing.Optional[typing.Dict[str, str]] = None,
    timeout: typing.Optional[typing.Union[float, typing.Tuple[float, float]]] = None
) -> Response: ...

def post(
    url: str,
    data: typing.Optional[typing.Dict[str, typing.Any]] = None,
    json: typing.Optional[typing.Dict[str, typing.Any]] = None,
    headers: typing.Optional[typing.Dict[str, str]] = None,
    timeout: typing.Optional[typing.Union[float, typing.Tuple[float, float]]] = None
) -> Response: ...

def put(
    url: str,
    data: typing.Optional[typing.Dict[str, typing.Any]] = None,
    headers: typing.Optional[typing.Dict[str, str]] = None,
    timeout: typing.Optional[typing.Union[float, typing.Tuple[float, float]]] = None
) -> Response: ...

def delete(
    url: str,
    headers: typing.Optional[typing.Dict[str, str]] = None,
    timeout: typing.Optional[typing.Union[float, typing.Tuple[float, float]]] = None
) -> Response: ... 