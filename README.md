Base64 and Quoted-Printable decoders for email
==============================================

This project contains a simple implementation in plain C of
Base64 and Quoted-Printable decoders for the MIME
Content-Transfer-Encoding standards defined in
[RFC 2045](https://tools.ietf.org/html/rfc2045).
Additionally, the Quoted-Printable decoder supports the modifications
for "encoded words" specified in 
[RFC 2047](https://tools.ietf.org/html/rfc2047).

While decoders like this already exist aplenty, anything I have
found in plain C or C++ tended to be either not to my taste
or part of a much larger library. The code here is extremely
lightweight and portable. It was written to be included in fast,
efficient mail filter applications.

Building
--------

The included Makefile builds a simple static object library
which can be linked with application code:
```
make
```

To run the unit tests, do
```
make test
```

Alternatively, just copy the header `decode.h` and source `decode.c`
to your project and compile them along with your application.

Encoders
--------

Corresponding encoders may appear here some day.

License
-------

Licensed under GPLv3. See the LICENSE file.
