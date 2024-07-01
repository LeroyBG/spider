# Basically just need to create a mapping between routes and functions,
# then create quality-of-life improvements
# for now only deal with hard routes without parameters, and the root path
from typing import overload, Literal
from io import BufferedIOBase
import json
from http.server import BaseHTTPRequestHandler
import socket

type parseMethod = Literal["json", "urlencoded"] | None
type HTTPMethod = Literal["GET", 
                           "POST", 
                           "PUT", 
                           "HEAD", 
                           "DELETE", 
                           "CONNECT", 
                           "OPTIONS", 
                           "TRACE", 
                           "PATCH"]
# program runs, user creates all their routes, then we handle http requests

class NoContentTypeBytes(Exception):
    pass

class Request(BaseHTTPRequestHandler):
    # From Express
    body: dict | None
    cookies: dict
    hostName: str
    ip: str
    method: str
    params: dict
    protocol: str
    query: dict # Might be for later implementation
    res: Response
    secure: bool
    signed_cookies: dict # Not sure about this one
    subdomains: list[str]
    xhr: bool

    def __init__(self, request, client_address, server, isParsing: parseMethod, method: HTTPMethod):
        super().__init__(request=request, client_address=client_address, server=server)
        self.cookies = self.__get_cookies__()
        self.hostName = socket.gethostbyaddr(self.client_address[0])
        self.ip = self.client_address[0]
        self.method = method
        self.params = self.__parse_params__()

        # "HTTP/1.0" -> "http", "HTTPS/1.0"-> "https"
        self.protocol = self.protocol_version[:self.protocol_version.find('/')].lower()
        self.secure = self.protocol == 'https'

        self.query = self.__parse_query__()

        # self.res should be set by function controlling handoff

        self.signed_cookies = self.__get_signed_cookies__()
        
        self.subdomains
        self.xhr = self.headers["X-Requested-Wit"] == "XMLHttpRequest"
        # Parse body...
    
    def __parse_params__(self):
        pass

    def __parse_query__(self):
        pass

    def __get_cookies__(self):
        pass
    
    def __get_signed_cookies__(self):
        pass
    # Checks if the specified content types are acceptable, based on the request’s
    # Accept HTTP header field. The method returns the best match, or if none of
    # the specified content types is acceptable, returns false (in which case,
    # the application should respond with 406 "Not Acceptable").

    # The type value may be a single MIME type string (such as “application/json”),
    # an extension name such as “json”, a comma-delimited list, or an array. For
    # a list or array, the method returns the best match (if any).
    @overload
    def accepts(self, type: str) -> bool:
        pass

    @overload
    def accepts(self, types: list[str]) -> bool:
        pass
    
    # Returns the specified HTTP request header field (case-insensitive match). 
    # The Referrer and Referer fields are interchangeable.
    def get(self, field: str) -> str:
        pass
    
    # This one seems weird
    # Returns the matching content type if the incoming request’s “Content-Type”
    # HTTP header field matches the MIME type specified by the type parameter.
    # If the request has no body, returns null. Returns false otherwise.
    def req_is(self, type: str):
        pass

    # This one seems difficult
    # Returns the value of param name when present.
    # Lookup is performed in the following order:
    # req.params
    # req.body
    # req.query
    # Optionally, you can specify defaultValue to set a default value if the
    # parameter is not found in any of the request objects.
    def param(self, name: str) -> str:
        pass
    



# TODO: When charset header is set, throw an error if that type of encoding
# isn't supported
type sendable = bytes | str | bool | list | dict
type jsonable = str | dict | list | int | bool |  None
class Response(BaseHTTPRequestHandler):
    headers: dict[str, str]
    code: int | None # i.e. 200 - ok
    # Need to store content length & type stuff separate
    content_type: str | None
    content_encoding : str | None
    def __init__(self, request, client_address, server):
        super().__init__(request=request, client_address=client_address, server=server)
        self.headers = {} # Will re-write existing "headers" instance variable
        self.code = None
        self.content_type = None
        self.content_encoding = None
    
    # TODO: important: add support for sending buffers
    # Sends specified message, defaults to utf-8 encoding
    # ignores characters that can't be encoded
    def send(self, msg: sendable) -> None:
        encoded: bytes | None
        match msg:
            case list():
                encoded = self.json(msg)
            case dict():
                encoded = self.json(msg)
            case bytes():
                encoded = self.__handle_bytes__(msg)
            case str():
                encoded = self.__handle_str__(msg)
            case bool():
                encoded = self.__handle_bool__(msg)
        
        if encoded == None: # No more work to do for list or dict
            return
        
        if "Content-Length" not in self.headers:
            self.headers["Content-Length"] = str(len(bytes))
        
        try:
            clen = int( self.headers["Content-Length"] )
        except:
            clen = len(bytes)

        self.__finalize_response_code__()
        self.__finalize_headers__()
        # Can raise an exception if write fails, but I think this should be exposed to sure
        self.wfile.write(encoded[:self.headers["Content-Length"]], clen)

    def __handle_bytes__(self, bytes: bytes) -> bytes:
        self.content_type = self.content_type or "application/octet-stream"
        
        return bytes
    
    def __handle_str__(self, str: str) -> bytes:
        self.content_type = self.content_type or "text/html"
        self.content_encoding = self.content_encoding or "utf-8"
        
        return str.encode(self.content_encoding, 'ignore')  
    
    def __handle_bool__(self, bool: bool) -> bytes:
        self.content_type = self.content_type or "text/plain"
        self.content_encoding = self.content_encoding or "utf-8"

        return str(bool).encode(self.content_encoding, 'ignore')
    
    def __handle__jsonable__(self, jsonable: jsonable) -> bytes:
        self.content_type = self.content_type or "application/json"
        self.content_encoding = self.content_encoding or "uft-8"

        stringified = json.dumps(jsonable)
        return stringified.encode(self.content_encoding, 'ignore')
        

    # Sends a JSON response. This method sends a response
    # (with the correct content-type) that is the parameter converted to a JSON
    # string using json.dumps().
    # The parameter can be any JSON type, including dict, list, str, bool,
    # int, or None.
    def json(self, msg: jsonable) -> None:
        # Will also set Content-Type header
        encoded = self.__handle_jsonable__(msg)

        self.content_type = "application/json"
        self.content_encoding = "utf-8"
        self.headers["Content-Length"]

        self.__finalize_response_code__()
        self.__finalize_headers__()
        self.wfile.write(encoded)
    
    # When a message is sent, we have to convert the headers to a object we
    # can use. This should only be used when the message is being sent
    def __finalize_headers__(self) -> None:
        for head in self.headers:
            self.send_header(head, self.headers[head])
        self.headers["Content-Type"] = f"{self.content_type or "text/plain"}; charset={self.content_encoding or "utf-8"}"
        self.end_headers()
    
    # When a message is sent, it needs a status code. This will default to 200
    # unless otherwise specified
    def __finalize_response_code__(self) -> None:
        if not self.code:
            self.send_response(200)
        else:
            self.send_response(self.code)
    
    # Sets the response HTTP status code to statusCode and sends the registered
    # status message as the text response body. If an unknown status code is
    # specified, the response body will just be the code number.
    def sendStatus(self, status: int) -> None:
        self.code = status
        self.send(self.responses[status])
    
    # Sets the HTTP status for the response
    def status(self, status: int) -> None:
        self.code = status


    # Set HTTP response headers
    @overload
    def set(self, head: str, val: str) -> None:
        self.headers[head] = val
    
    @overload
    def set(self, headers: dict[str, int]) -> None:
        for head in headers:
            val = headers[head]
            self.headers[head] = val

    # Returns the HTTP response header specified by field.
    # The match is case-insensitive.
    def get(self, field: str) -> str | None:
        # Inefficient but necessary to guarantee case-insensitivity
        # I don't wanna store a whole other dictionary of lowercase headers...
        # but could be necessary for future speed improvement?
        for head in self.headers:
            if head.lower() == field.lower():
                return self.headers[head]
        return None
    
    # Redirects to the URL derived from the specified path, with specified status,
    # a positive integer that corresponds to an HTTP status code. 
    # If not specified, status defaults to “302 “Found”.
    @overload
    def redirect(self, path: str) -> None:
        self.status(302)
        self.set("Location", path)
        self.__finalize_headers__()

    @overload
    def redirect(self, status: int, path: str) -> None:
        self.status(status)
        self.set("Location", path)
        self.__finalize_headers__()

    # Ends the response process. Use to quickly end the response without any data
    def end(self) -> None:
        self.__finalize_response_code__()
        self.__finalize_headers__()
        return
        



# A function that handles requests
type callback = callable[[Request, Response], None]

# A mapping of routes to functions
type route_mapping = dict[str, callback] 

# A mapping of types of routes (i.e., GET, POST, etc.) to route_mappings
type route_type_mapping = dict[HTTPMethod, route_mapping]

class Router():
    mappings: route_type_mapping
    def __init__(self) -> None:
        self.mappings = {
            "GET": {},
            "POST": {},
            "PUT": {},
            "HEAD": {},
            "DELETE": {},
            "CONNECT": {},
            "OPTIONS": {},
            "TRACE": {},
            "PATCH": {}
        }
    
    def get(self, route: str, callback: callback):
        self.mappings["GET"][route] = callback

    def post(self, route: str, callback: callback):
        self.mappings["POST"][route] = callback
        
    def put(self, route: str, callback: callback):
        self.mappings["PUT"][route] = callback

    def head(self, route: str, callback: callback):
        self.mappings["HEAD"][route] = callback

    def delete(self, route: str, callback: callback):
        self.mappings["DELETE"][route] = callback

    def connect(self, route: str, callback: callback):
        self.mappings["CONNECT"][route] = callback

    def options(self, route: str, callback: callback):
        self.mappings["OPTIONS"][route] = callback

    def trace(self, route: str, callback: callback):
        self.mappings["TRACE"][route] = callback

    def path(self, route: str, callback: callback):
        self.mappings["PATCH"][route] = callback

# example usage:
# router = Spider.Router()
# router.get("/hello", handle_hello)

