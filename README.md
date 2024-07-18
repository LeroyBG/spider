# Spider

Spider is a minimal framework for building web APIs with Python.
Based off the
[Express.js 4.x](https://expressjs.com/en/4x/api.html#res.download) API, Spider
provides numerous of the quality-of-life features and abstractions that make
building your app faster and easier.

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
