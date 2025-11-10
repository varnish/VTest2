# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

VTest2 is a standalone HTTP testing program, originally derived from Varnish's varnishtest. It's designed to test HTTP clients, servers, and proxies using a domain-specific scripting language (`.vtc` files). This is the second iteration that maintains better synchronization with Varnish-Cache while being usable independently.

## Build Commands

### Basic Build
```bash
make vtest          # Build without Varnish support
make test           # Build and run all tests
make clean          # Remove build artifacts
```

### Build with Varnish Support
```bash
make varnishtest VARNISH_SRC=/path/to/varnish-cache
```

### Generated Files
The build process generates two files that must exist before compilation:
- `src/teken_state.h` - Generated from `src/sequences` using awk
- `src/vtc_h2_dectbl.h` - Generated from `src/tbl/vhp_huffman.h` using Python

### Syncing with Varnish-Cache
```bash
make update         # Pull updates from Varnish-Cache repository
                    # Set VARNISHSRC env var to use local repo instead of cloning
```

## Code Architecture

### Directory Structure
- **lib/** - Shared utility library code from Varnish-Cache (vsb, vqueue, vtcp, etc.)
- **src/** - Core VTest implementation
  - `vtc_main.c` - Entry point, test execution orchestration, parallel test runner
  - `vtc.c` - Core test execution, macro expansion, command dispatch
  - `vtc_http.c/vtc_http.h` - HTTP/1.1 client/server implementation
  - `vtc_http2.c` - HTTP/2 support
  - `vtc_client.c` - Client command implementation
  - `vtc_server.c` - Server command implementation
  - `vtc_process.c` - Process spawning and management with terminal emulation
  - `vtc_barrier.c` - Synchronization primitives for tests
  - `vtc_logexp.c` - Log expectation matching (conditional, Varnish-specific)
  - `vtc_varnish.c` - Varnish-specific testing (conditional compilation)
  - `vtc_haproxy.c` - HAProxy-specific testing
  - `tbl/` - Table-driven code generation (H2 frames, settings, errors)
- **tests/** - Test suite (`.vtc` files)
- **tools/sync/** - Scripts for syncing code with Varnish-Cache

### Command System
Commands are registered via `cmds.h` using X-macros:
- **CMD_GLOBAL**: Available everywhere (barrier, delay, shell, include)
- **CMD_TOP**: Top-level test commands (client, server, process, varnish, haproxy, etc.)

The extensible command system allows loading shared libraries via `-E extension_shlib` to add custom commands at runtime using `add_cmd()`.

### Core Concepts

**Test Execution Model:**
Tests are executed in forked child processes with their own temporary directories. The main process (`vtc_main.c`) orchestrates parallel execution (configurable via `-j`), manages timeouts, and collects results via pipes.

**Macro System:**
VTest has a powerful macro expansion system supporting:
- Static macros defined via `-D name=val`
- Dynamic macros defined in test scripts
- Function macros (e.g., `${date}`, `${string,repeat,N,text}`)
- Automatic macros for servers/clients (sNAME_addr, sNAME_port, sNAME_sock)

**Session Abstraction:**
HTTP clients and servers share common session handling code (`vtc_sess.c`, `sess_process()`) with pluggable connect/disconnect callbacks. This enables code reuse between client, server, and tunneling modes.

**Terminal Emulation:**
Process commands include a full terminal emulator (`teken.c`) supporting VT220 escape sequences for testing interactive programs and screen output.

## Test File Format

Tests are `.vtc` files that must start with `vtest` or `varnishtest` followed by a description:
```vtc
vtest "Test description"

server s1 {
    rxreq
    txresp
} -start

client c1 -connect ${s1_sock} {
    txreq
    rxresp
    expect resp.status == 200
} -run
```

## Build Dependencies

### Linux
- libpcre2-dev
- zlib

### macOS
Libraries typically available via Homebrew

## Platform-Specific Notes

- **Linux**: Uses `dlopen()` by name for extensions
- **macOS**: Bound but non-listening sockets timeout instead of refusing, so bad_backend_fd is closed
- **FreeBSD jails**: localhost/127.0.0.1 becomes the jail's IP

## Conditional Compilation

Several features are conditionally compiled:
- `VTEST_WITH_VTC_VARNISH` - Varnish integration (vtc_varnish.c)
- `VTEST_WITH_VTC_LOGEXPECT` - Log expectation matching
- `VTEST_WITH_VTC_VSM` - Varnish Shared Memory support

## Development Notes

- Code in `lib/` is synced from Varnish-Cache - don't modify directly
- Extensions use `add_cmd(name, function, flags)` to register new commands
- Test names in `tests/` follow pattern `a[0-9]{5}.vtc`
- Use `leave_temp` options (`-l`, `-L`) to preserve test directories for debugging
- The codebase uses Varnish's utility libraries: miniobj for object checking, vsb for string buffers, vqueue for linked lists
