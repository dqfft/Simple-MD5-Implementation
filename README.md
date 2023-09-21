# Simple-MD5-Implementation
A single header for converting bytes -> MD5 hex digest in C

``` C
#include "md5.h"
// static void md5_hexdigest(const char *input, char output[33]);
...
char [33]digest;
char *text ="Hello, World!";
md5_hexdigest(text, digest);
printf("digest: %s\n", digest);
// digest: "65a8e27d8879283831b664bd8b7f0ad4"
```
[RFC 1321](https://www.rfc-editor.org/rfc/rfc1321): MD5 Message-Digest Algorithm - April 1992
