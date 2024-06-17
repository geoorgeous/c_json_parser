# c_json_parser

- Straight-forward, simple, clean API.
- Zero memory leaks reported via [Deleaker](https://www.deleaker.com/). Test executable built with `gcc 12.2.0` (MinGW) Options: `-std=c99 -pedantic-errors -Wall -Wextra -Werror`.
- Does not support JSON with comments.
- All JSON values represented using single handle `struct json_value_st*`.

## Example Usage
JSON:
```JSON
{
  "someNumber": 42.0,
  "someArray": [
    true,
    "Hello, World",
    117
  ],
  "nothing": null
}
```
C:
```C
#include <stdio.h>
#include "json_parser.h"

struct json_value_st* json_root = json_parse(source, source_length);

if (json_root) {
  struct json_value_st* number_property = json_object_get(json_root, "someNumber");
  if (json_is_number(number_property))
    printf("Error: expected property 'someNumber' to be a number!\n");
  else
    printf("Number value: %d\n", json_number(number_property));

  struct json_value_st* array_property = json_object_get(json_root, "someArray");
  struct json_value_st* string_element = json_array_get(array_property, 2);
  printf("String at index 2: %s\n", json_string(string_element));

  json_free(&json_root);
}

```
## Limitations
- Does not yet support JSON exporting.
- Parsing errors are not all that helpful. For now if parsing fails, double check JSON validity via [an online validator](https://www.toptal.com/developers/json-formatter).

Please report any bugs or problems!
