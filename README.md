# VTest2

HTTP test program derived from Varnish's varnishtest. Tests HTTP clients, servers, and proxies using `.vtc` test scripts.

Plug-in replacement for [vtest1](https://github.com/vtest/VTest).

## Building

```bash
make vtest                              # Build standalone
make varnishtest VARNISH_SRC=/path      # Build with Varnish support
make test                               # Build and run tests
```

### Dependencies

**Linux:** libpcre2-dev, zlib, libssl-dev
**macOS:** Same via Homebrew (OpenSSL via `brew install openssl@3`)

## Usage

```bash
./vtest tests/a00001.vtc                # Run single test
./vtest -j4 tests/*.vtc                 # Run tests in parallel
```

Test files start with `vtest` or `varnishtest` followed by a description. See `tests/` directory for examples.

## Syncing with Varnish-Cache

For maintainers: `make update` syncs shared code from Varnish-Cache. Set `VARNISHSRC` to use a local repo instead of cloning.

See `CLAUDE.md` for architecture details and `TLS-IMPL.md` for TLS support documentation.
