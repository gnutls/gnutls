# crau

`crau` is a small helper library to define
[crypto-auditing][crypto-auditing] probes in C applications. The
library shall be either statically linked or bundled into the
application itself.

## Getting started

1. Define `ENABLE_CRYPTO_AUDITING` to 1, e.g., through `<config.h>`

1. Include `<crau/crau.h>`. One of the C files should define
   `CRAU_IMPLEMENTATION` to get the functions defined.

1. (Optional) Customize the implementation with configuration macros,
   e.g., `CRAU_CONTEXT_STACK_DEPTH` for your needs. See
   `<crau/crau.h>` for the details.

1. Instrument the code as follows. See `<crau/crau.h>` and
   `<crau/macros.h>` for the documentation:

```c
/* Public key signing operation starts (but the algorithm is not known yet) */
crau_new_context_with_data(
  "name", CRAU_STRING, "pk::sign",
  NULL)
...
/* Signing algorithm and bits are known at this point */
crau_data(
  "pk::algorithm", CRAU_STRING, "mldsa",
  "pk::bits", CRAU_WORD, 1952 * 8,
  NULL)

/* Do the operation */
sig = mldsa_sign(...);

/* Pop the operation context */
crau_pop_context();
```

## Low level macros

Instead of using those helper functions (`crau_*`), it is also
possible to directly instrument the library with `CRAU_` macros
defined in `macros.h`:

```c
/* Public key signing operation starts (but the algorithm is not known yet) */
CRAU_NEW_CONTEXT_WITH_DATAV(
  (crau_context_t)this_function,
  (crau_context_t)parent_function,
  CRAU_STRING_DATA("name", "pk::sign"));
...
/* Signing algorithm and bits are known at this point */
CRAU_DATAV(
  (crau_context_t)this_function,
  CRAU_STRING_DATA("pk::algorithm", "mldsa"),
  CRAU_WORD_DATA("pk::bits", 1952 * 8))

/* Do the operation */
sig = mldsa_sign(...);
```

Note that those macros don't do context management.

## License

MIT or Unlicense

[crypto-auditing]: https://github.com/latchset/crypto-auditing
