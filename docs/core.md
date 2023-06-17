# Core API

The core API call are the function {func}`pem.parse` and the its convenience helper {func}`pem.parse_file`:

```
import pem

with open("cert.pem", "rb") as f:
   certs = pem.parse(f.read())

# or:

certs = pem.parse_file("cert.pem")
```

The function returns a list of valid {ref}`PEM objects <pem-objects>` found in the string supplied.

- They can be transformed using `str(obj)` or `obj.as_text()` into Unicode text (`str`),
- or using `obj.as_bytes()` into bytes.
- Additional you can obtain the SHA-1 hexdigest using `obj.hashdigest()` for quick comparison of objects.
