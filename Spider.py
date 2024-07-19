# Basically just need to create a mapping between routes and functions,
# then create quality-of-life improvements
# for now only deal with hard routes without parameters, and the root path
from typing import overload, Literal, Callable, Self
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
from http.cookies import SimpleCookie
from urllib import parse
import re

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

class Request():
    # From Express
    body: dict | None
    # cookies: dict
    hostname: str
    ip: str
    method: str
    params: dict
    protocol: str
    query: dict # Might be for later implementation
    # res: Response
    secure: bool
    # signed_cookies: dict # Not sure about this one
    subdomains: list[str]
    xhr: bool
    get: Callable[[str], str]
    method: HTTPMethod # Same as self.command, just for express compatibility

    # No more inheritance! -- below are all copied from BaseHTTPRequestHandler
    # Could use Object.assign() method in the future? Not sure if that's better
    # than doing it explicitly
    client_address: tuple[str, int]
    server: HTTPServer
    requestline: str
    command: HTTPMethod
    path: str # Client request path
    headers: dict # Not sure about this type definition
    server_version: str
    sys_version: str
    # error_message_format -- ignore for now
    error_content_type: str
    protocol_version: str
    
    def __init__(self, client_address, server, parse_method: parseMethod,
                 method: HTTPMethod, is_cookie_parsing: bool,
                 client_request_path: str, defined_route_path: str,
                 requestline: str, headers: dict, server_version: str,
                 sys_version: str, error_content_type: str,
                 protocol_version: str):
        
        # Copy down things that used to be inherited
        self.client_address = client_address
        self.server = server
        self.requestline = requestline
        self.command = self.method = method
        self.path = client_request_path
        self.headers = headers
        self.server_version = 'Spider/0.1'
        self.sys_version = sys_version
        self.error_content_type = error_content_type
        self.protocol_version = protocol_version

        # Get Express variables
        # self.cookies = self.__get_cookies__() if is_cookie_parsing else None
        self.hostname = socket.gethostbyaddr(self.client_address[0])
        self.ip = self.client_address[0]
        # self.method already initialized
        self.params = Router.__parse_params__(client_request_path, 
                                              defined_route_path)
        # "HTTP/1.0" -> "http", "HTTPS/1.0"-> "https"
        self.protocol = self.protocol_version[:self.protocol_version.find('/')].lower()
        self.query = self.__parse_query__()
        # self.res should be set by function controlling handoff
        self.secure = self.protocol == 'https'
        # self.signed_cookies = self.__get_signed_cookies__()
        # self.subdomains -- don't know how to do this one for now
        self.xhr = self.headers["X-Requested-Wit"] == "XMLHttpRequest"
        self.get = self.headers.get
        
        # Parse body...
        if parse_method:
            self.body = self.__parse_body__(parse_method)
        else:
            self.body = None

        
    def __parse_body__(self, parse_method: parseMethod) -> dict | None:
        try: # If the requester doesn't specify content-length, return None
            clen = int(self.headers["Content-Length"])
        except:
            return None
        raw_body = self.rfile.read( clen )

        if parse_method == "json":
            return json.loads( raw_body )
        elif parse_method == "urlencoded":
            return parse.parse_qs( raw_body )
        else:
            return None
    
    # Returns a dict of query parameters
    # Should I expose fact that I'm using urlparse to user so they know what to expect?
    def __parse_query__(self):
        return parse.parse_qs(parse.urlparse(self.path).query)

    # I don't want to do this right now
    def __get_cookies__(self):
        cookie = SimpleCookie()
        cookie.load()
    
    # This either
    def __get_signed_cookies__(self):
        cookie = self.headers["Cookie"]

    # NOT IN USE: Will take forever to implement
    # Checks if the specified content types are acceptable, based on the request’s
    # Accept HTTP header field. The method returns the best match, or if none of
    # the specified content types is acceptable, returns false (in which case,
    # the application should respond with 406 "Not Acceptable").

    # The type value may be a single MIME type string (such as “application/json”),
    # an extension name such as “json”, a comma-delimited list, or an array. For
    # a list or array, the method returns the best match (if any).

    # @overload
    # def accepts(self, type: str) -> bool:
    #     pass

    # @overload
    # def accepts(self, types: list[str]) -> bool:
    #     pass
    
    # Returns the specified HTTP request header field (case-insensitive match). 
    # The Referrer and Referer fields are interchangeable.
    
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
    def param(self, name: str) -> str | None:
        return self.params[name] if name in self.params else None
    



# TODO: When charset header is set, throw an error if that type of encoding
# isn't supported
type sendable = bytes | str | bool | list | dict
type jsonable = str | dict | list | int | bool |  None
class Response():
    handler: BaseHTTPRequestHandler # ChatGPT's suggestion
    headers: dict[str, str]
    code: int | None # i.e. 200 - ok
    responses: dict # Inherited from BaseHTTPRequestHandler
    # Need to store content length & type stuff separate
    content_type: str | None
    content_encoding : str | None
    def __init__(self, handler: BaseHTTPRequestHandler):
        self.headers = {} # Will re-write existing "headers" instance variable
        self.code = None
        self.content_type = None
        self.content_encoding = None
        self.handler = handler
        self.responses = handler.responses
    
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
            self.headers["Content-Length"] = str(len(encoded))
        
        try:
            clen = int( self.headers["Content-Length"] )
        except:
            clen = len(bytes)
            self.headers["Content-Length"] = str(clen)

        self.__finalize_response_code__()
        self.__finalize_headers__()
        # Can raise an exception if write fails, but I think this should be
        # exposed to user
        self.handler.wfile.write(encoded)

    def __handle_bytes__(self, bytes: bytes) -> bytes:
        self.content_type = self.content_type or "application/octet-stream"
        
        return bytes
    
    def __handle_str__(self, string: str) -> bytes:
        self.content_type = self.content_type or "text/html"
        self.content_encoding = self.content_encoding or "utf-8"
        
        return string.encode(self.content_encoding, 'ignore')  
    
    def __handle_bool__(self, boolean: bool) -> bytes:
        self.content_type = self.content_type or "text/plain"
        self.content_encoding = self.content_encoding or "utf-8"

        return str(boolean).encode(self.content_encoding, 'ignore')
    
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
    def json(self, body: jsonable) -> None:
        # Will also set Content-Type header
        encoded = self.__handle__jsonable__(body)

        self.content_type = "application/json"
        self.content_encoding = "utf-8"
        self.headers["Content-Length"]

        self.__finalize_response_code__()
        self.__finalize_headers__()
        self.handler.wfile.write(encoded)
    
    # When a message is sent, we have to convert the headers to a object we
    # can use. This should only be used when the message is being sent
    def __finalize_headers__(self) -> None:
        for head in self.headers:
            self.handler.send_header(head, self.headers[head])
        self.headers["Content-Type"] = f"{self.content_type or "text/plain"}; charset={self.content_encoding or "utf-8"}"
        self.handler.end_headers()
    
    # When a message is sent, it needs a status code. This will default to 200
    # unless otherwise specified
    def __finalize_response_code__(self) -> None:
        if not self.code:
            self.handler.send_response(200)
        else:
            self.handler.send_response(self.code)
    
    # Sets the response HTTP status code to statusCode and sends the registered
    # status message as the text response body. If an unknown status code is
    # specified, the response body will just be the code number.
    def sendStatus(self, code: int) -> None:
        self.code = code
        if code not in self.responses:
            self.end()
        else:
            self.send(self.responses[code])
    
    # Sets the HTTP status for the response
    def status(self, status: int) -> Self:
        self.code = status
        return self

    # Set HTTP response headers
    @overload
    def set(self, head: str, val: str) -> Self:
        self.headers[head] = val
        return self
    
    @overload
    def set(self, headers: dict[str, int]) -> Self:
        for head in headers:
            val = headers[head]
            self.headers[head] = val
        return self

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
        self.headers["Location"] = path
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
type callback = Callable[[Request, Response], None]

# A mapping of routes to functions
type route_mapping = dict[str, callback] 

# A mapping of types of routes (i.e., GET, POST, etc.) to route_mappings
type route_type_mapping = dict[HTTPMethod, route_mapping]

class Router():
    mappings: route_type_mapping
    parse_method: parseMethod
    is_cookie_parsing: bool
    current_request: BaseHTTPRequestHandler
        
    def __init__(self, is_cookie_parsing=False) -> None:
        self.parse_method = None
        self.is_cookie_parsing = is_cookie_parsing
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
    
    def __add_route__(self, method: str, route: str, callback: callback):
        self.mappings[method][route] = callback # I guess patterns are hashable?
    
    # Take a client request and return the matched path and callback for it if one is found
    def __match_request_to_callback__(self, request_type: HTTPMethod, 
                                    request: str) -> tuple[str, callback] | None:
        # Analyze the request path and ignore query component
        path: str = parse.urlparse(request).path
        for defined_route_path in self.mappings[request_type]:
            # TODO: Pre-compile regex and use named capture groups so we don't
            # have to keep the original defined route path

            match_params = self.__parse_params__(path, defined_route_path)
            if match_params == None:
                continue

            else:
                return (defined_route_path, self.mappings[request_type][defined_route_path])
        return None
    
    # TODO: Allow user to specify config options like parseMethod,
    # is_cookie_parsing, etc.
    def __handle_incoming_request__(self, command: HTTPMethod, 
                                    request_path: str, 
                                    handler: BaseHTTPRequestHandler):
        callback = self.__match_request_to_callback__(command, request_path)
        # Callback is a tuple if a match is found
        if callback:
            res = Response(handler=handler)
            req = Request(client_address=handler.client_address,
                          server=handler.server, parse_method=self.parse_method,
                          is_cookie_parsing=False,
                          client_request_path=request_path,
                          defined_route_path=callback[0],
                          requestline=handler.requestline,
                          headers=handler.headers,
                          server_version=handler.server_version,
                          sys_version=handler.sys_version,
                          error_content_type=handler.error_content_type,
                          protocol_version=handler.protocol_version,
                          method=command)
            # THE ISSUE IS THE LINE ABOVE ^
            callback_fn = callback[1]
            callback_fn(req, res)
            return

    def parse(self, parse_method: parseMethod) -> None:
        valid_parse_methods = ['urlencoded', 'json']
        if parse_method not in valid_parse_methods:
            s_parse_methods = ''.join(valid_parse_methods)
            valid_parse_methods
            raise Exception(f"{parse_method} not one of {s_parse_methods}")
        
        self.parse_method = parse_method
    
    def listen(self, port: int):
        router = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                # router.current_request = self
                router.__handle_incoming_request__("GET", self.path, self)
            
            def do_POST(self):
                # router.current_request = self
                router.__handle_incoming_request__("POST", self.path, self)
            
            def do_PUT(self):
                # router.current_request = self
                router.__handle_incoming_request__("PUT", self.path, self)
            
            def do_HEAD(self):
                # router.current_request = self
                router.__handle_incoming_request__("HEAD", self.path, self)
            
            def do_DELETE(self):
                # router.current_request = self
                router.__handle_incoming_request__("DELETE", self.path, self)
            
            def do_CONNECT(self):
                # router.current_request = self
                router.__handle_incoming_request__("CONNECT", self.path, self)
            
            def do_OPTIONS(self):
                # router.current_request = self
                router.__handle_incoming_request__("OPTIONS", self.path, self)
            
            def do_TRACE(self):
                # router.current_request = self
                router.__handle_incoming_request__("TRACE", self.path, self)

            def do_PATH(self):
                # router.current_request = self
                router.__handle_incoming_request__("PATH", self.path, self)
        
        httpd = HTTPServer(('localhost', port), Handler)
        httpd.serve_forever()
    

    def get(self, route: str, callback: callback):
        self.__add_route__("GET", route, callback)

    def post(self, route: str, callback: callback):
        self.__add_route__("POST", route, callback)
        
    def put(self, route: str, callback: callback):
        self.__add_route__("PUT", route, callback)

    def head(self, route: str, callback: callback):
        self.__add_route__("HEAD", route, callback)

    def delete(self, route: str, callback: callback):
        self.__add_route__("DELETE", route, callback)

    def connect(self, route: str, callback: callback):
        self.__add_route__("CONNECT", route, callback)

    def options(self, route: str, callback: callback):
        self.__add_route__("OPTIONS", route, callback)

    def trace(self, route: str, callback: callback):
        self.__add_route__("TRACE", route, callback)

    def patch(self, route: str, callback: callback):
        self.__add_route__("PATCH", route, callback)

    def all(self, route: str, callback: callback):
        for c in ["GET", "POST", "PUT", "HEAD", "DELETE", "CONNECT", "OPTIONS",
                 "TRACE", "PATCH"]:
            self.__add_route__(c, route, callback)


    # We need a dummy regex with no captures that takes a route with parameters
    # like '/books/:section/:number/' and converts it to a regex that accepts
    # any url path with those parameters filled in.
    # Valid characters for variable values are [^/-.]
    # Note: when using routes with params, we apply very similar regex to the
    # same path twice - maybe fix this one day
    def __convert_param_route_to_dummy_regex__(defined_route_path: str) -> str:
        # The only character we handle in a special way is '*', e.g. '/foo/*',
        # which corresponds to the regex '/foo/.*'
        valid_name_chars = re.compile("[A-Za-z0-9_]")
        literal_chars = '.-'
        parsing_param = False
        regex_str = ''
        for c in defined_route_path:
            if c == ':':
                if parsing_param: # Treat ':' like any other valid character
                    continue
                else: # start replacing a param name with
                    parsing_param = True
                    regex_str += '[^-./]+'
            elif not valid_name_chars.match(c): # Stop parsing param name
                if parsing_param:
                    parsing_param = False
                    

                if c in literal_chars:
                    regex_str += f'\\{c}'
                    # If this character is a character that should be
                    # interpreted literally, escape it
                    # ':hello+' becomes '[^-./]+\+'
                else:
                    regex_str += c
            else:
                if parsing_param:
                    continue
                else:
                    regex_str += c
        return f'^{regex_str}$'

    # Both matches paths and parses params
    # Returns none if path doesn't match
    # This one is a lot of heavy lifting:
    # A url can contain parameters, like "/users/:userId/books/:bookId" (2 params)
    # Do some regex with captures?? idk
    # TODO: Make this a static class method that doesn't have 'self' parameter
    @staticmethod
    def __parse_params__(client_request_path: str, defined_route_path: str) -> dict | None:
        # Scan through the route and generate a Regex expression
        # First approach: when a ':' is encountered, scan the next n alphanumeric
        # characters and replace them with the capture group '([A-Za-z0-9_])'
        # Edge case: when the parameter isn't present?        
        
        parsingParam = False
        regexStr = ''
        valid_param_name_char = re.compile("[A-Za-z0-9_]")
        invalid_val_chars = '-.'
        paramNames: list[str] = []
        currentParamName = ''
        for c in defined_route_path:
            valid_name_char = valid_param_name_char.match(c) 
            if c == ':':
                # If we're already parsing a param and we come to a colon, 
                # treat it like any other valid character, so the param's name
                # will be 'books:id' (probably a user error, but more
                # transparent this way)
                if parsingParam:
                    currentParamName += c
                else:
                    parsingParam = True
                    regexStr += '([^-./]+)'
                    currentParamName = ''
            elif not valid_name_char: # Stop parsing current param
                if parsingParam:
                    parsingParam = False
                    paramNames.append(currentParamName)
                    
                if c == '.':
                    regex_str += f'\\.'
                    # If this character is a character that should be
                    # interpreted literally, escape it
                    # ':hello.' becomes '[^-./]+\.'
                else:
                    regexStr += c
            else: # Is a valid param name character
                if parsingParam:
                    currentParamName += c
                else:
                    regexStr += c
        if parsingParam:
            parsingParam = False
            paramNames.append(currentParamName)
        
        param_pattern = re.compile(f'^{regexStr}$')
        param_values = param_pattern.match(client_request_path)

        if param_values == None: # If the route didn't match
            return None
        else:
            param_values = param_values.groups()
        
        params: dict = {}
        for n, v in zip(paramNames, param_values):
            params[n] = v
        return params


if __name__ == '__main__':
    router = Router()

    def root_get(req: Request, res: Response):
        res.status(200).send("Hello World!")
    
    router.get("/", root_get)
    router.listen(3000)