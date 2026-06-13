# examples

End-to-end test suites for libsignal-zig across multiple languages. Each one
exercises every protocol operation exposed by the C API: EC keys and XEdDSA,
ML-KEM-1024, X3DH + Double Ratchet, Sender Keys (group), Sealed Sender V1
and V2, Fingerprints, Username ZK proofs, and Account entropy pool.

**Prerequisite for all examples:** build the library from the repo root first.

```sh
zig build                        # debug
zig build -Doptimize=ReleaseFast # optimized
```

This produces `zig-out/lib/libsignal.dylib` (or `.so` on Linux) that every
example links against.

---

| Example | Language | FFI mechanism | Details |
|---------|----------|---------------|---------|
| [`c/`](c/) | C99 | direct `#include` of `libsignal.h` | [README](c/README.md) |
| [`cpp/`](cpp/) | C++ 17 | direct `#include` of `libsignal.h` | [README](cpp/README.md) |
| [`go/`](go/) | Go | CGo | [README](go/README.md) |
| [`java/`](java/) | Java 17+ | JNA 5.14 | [README](java/README.md) |
| [`ruby/`](ruby/) | Ruby 3+ | `ffi` gem | [README](ruby/README.md) |
| [`rust/`](rust/) | Rust | hand-written `extern "C"` bindings, `libc` crate | [README](rust/README.md) |
| [`zig/`](zig/) | Zig 0.16 | native Zig API | [README](zig/README.md) |

Adding a new language? Create a subdirectory with its own README following the
same structure, and add one row to the table above. The main repo README does
not need to change.
