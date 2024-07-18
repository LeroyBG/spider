# Spider

Spider is a minimal framework for building web APIs with Python.

## Usage

### Minimal Example

```Python
from Spider import Router, Request, Response

def root_get(req: Request, res: Response):
    res.status(200)
    res.send(f'hello, {req.client_address}')

router = Router()
router.get("/", root_get)
router.listen(3000)
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
