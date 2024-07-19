# Spider

Spider is a minimal framework for building web APIs with Python.
Based off the [Express.js 4.x](https://expressjs.com/en/4x/api.html) API,
Spider provides numerous of the quality-of-life features and abstractions that
make building your app faster and easier.

## Key Features

### Request Handling

- Include route parameters with `:paramname` and access then through
  `req.params["paramname"]`
- Automatic body parsing (supports json and urlencoded)
- Automatic query parsing

### Response Handling

- Easily send responses with `res.send` and `res.json` methods (both
  automatically set content length and latter sets content-type)
- Chain response methods, i.e. `res.status(200).send("hello")`

## Usage

### Minimal Example

```Python
from Spider import Router, Request, Response

def root_get(req: Request, res: Response):
    res.status(200).send(f'hello, {req.client_address}')

router = Router()
router.get("/", root_get)
router.listen(3000)
```

### Multiple Methods on a Route

```Python
router = Router()
def root_get(req: Request, res: Response):
    # Same as before...
router.get("/", root_get)

def root_put(req: Request, res: Response):
    res.status(201).json({
        "username": "blah",
        "password": 123
    })
router.put("/", root_put)

# And so on...
```

### Defining Multiple Routes

```Python
def root_get(req: Request, res: Response):
    # ...
router.get("/", root_get)

def root_put(req: Request, res: Response):
    # ...
router.put("/", root_get)

def docs_get(req: Request, res: Response):
    # ...
router.get("/docs", docs_get)

def docs_upload_by_id(req: Request, res: Response):
    # ...
router.post("/docs/:id", docs_upload_by_id)
```

## Route Matching

Valid characters for a route are

- word characters: \[a-zA-Z0-9_\]
- backslashes, '\\'
- the characters, ?, +, *, and ()
- the character, ':' to denote parameters

If a route contains characters not this set, it will not be compiled to regex
and will instead be interpreted literally, meaning an exact match will be
needed.

A route name is processed using the following steps

1. Prepend the character '^' to the beginning of the string and '$' to the end
2. Compile the string as a regex using `re.compile()`
3. Check if the current route matches the compiled pattern

Routes are consulted in the order they're listed, meaning the route `"*"` will
process every request your server receives if it's listed first. If you list
the route `"*"` after all other routes, it will match every route that doesn't
match one of those routes.

## API

### Request

The `Request` object represents the HTTP request and provides useful instance
variables and methods for parsing and retrieving request information.

#### Request Instance Variables

##### `req.body`

A `dict` containing key-value pairs of data submitted in the request body.
Is `None` by default, but can be configured using
[`Router.use([parse method])`](# `router.use`).

```Python
def cart_add(req: Request, res: Response):
    req.body["itemName"] # E.g. "carrot"
    req.body["details"]["code"] # and so forth...
```

##### `req.hostname`

Contains server's hostname.

##### `req.ip`

Returns client's ip address.

##### `req.method`

A string representing the request method/command: GET, POST, PUT, etc.

##### `req.params`

A `dict` containing key-value pairs of data sent in place of parameters in the
specified path.

```Python
# "/books/:category/:popularityRank"
def get_book_by_popularity(req: Request, res: Response):
    category = req.params["category"] # E.g. 'nonfiction'
    rank = req.params["popularityRank"] # E.g. 47
router.get("/books/:category/:popularityRank", get_book_by_popularity)
```

The `.` characters is interpreted literally, which makes it easy to put params
next to each other.

```Python
# "/dict.:category.:sub_category"
def get_object_properties(req: Request, res: Response):
    category = req.params["category"]
    sub = req.params["sub_category"]
    res.json(dictionary[category][sub])
```

##### `req.path`

Contains a string representation of the path part of the request url. For
example, a request sent to `"/course?id=a123123&date=2012"` will have
`req.path` equal to `"/course"`.

##### `req.protocol'

Contains the request protocol string: either `"http"` or `"https"`.
*Note:* this property currently a constant with value `"http"`.

##### `req.query`

A `dict` containing the result of parsing the request query via
`urllib.parse.parse_qs`.

```Python
def convert_query_to_json(req: Request, res: Response):
    res.json(req.query)
# E.g., if the request url is "/course?id=a123123&date=2012",
# req.query is {"id": "123123", "date": "2012"}
```

##### `req.secure`

A boolean containing the value of `req.protocol == 'https'`.
*Note:* this property currently a constant with value `False`.

##### `req.xhr`

A Boolean property that is true if the request’s X-Requested-With header field is “XMLHttpRequest”.

#### Request Instance Methods

`req.get(field)`

Retrieves the value of the specified http header. Same as
`req.headers.get(field)`.

##### Additional Request Variables

The `Request` class also copies the following instance variables from
[`BaseHTTPRequestHandler`](https://docs.python.org/3/library/http.server.html)
for troubleshooting: `client_address`, `server`, `requestline`, `command`,
`path`, `headers`, `server_version`, `sys_version`, `error_content_type`, and
`protocol_version`.

### Response

### Router

#### Router Instance Variables

#### `router.use`
