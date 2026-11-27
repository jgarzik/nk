# Unsafe code rules

1. **Wrapper first.** Put the `unsafe` in one small function with a safe
   signature, and call that. A safe function that can cause undefined
   behaviour is a bug. So a safe function takes a raw pointer only as a
   key (compared, stored, looked up) or after checking it against what
   the kernel holds (a table of its own objects); one that would
   dereference a pointer it cannot check is `unsafe fn`, and a function
   that turns a raw pointer into a reference (`&'a T`) always is. A
   type whose only constructor is `unsafe` may have safe methods over
   the pointer it holds: the constructor's contract covers them.
2. **Say why.** Every `unsafe` block carries a `// SAFETY:` comment, every
   `unsafe fn` a `# Safety` section. Both are enforced by clippy.
3. **No `static mut`.** Use atomics, a lock, or per-CPU state.
4. **Driver memory is foreign memory.** Objects a driver can see
   (`DEVICE_OBJECT`, `IRP`, ...) are reached through raw pointers and
   read or written field by field. Never form `&` or `&mut` to them: the
   driver may write at any time, which a Rust reference forbids.
5. **Device and firmware memory** is read and written with volatile
   accesses through raw pointers, never through references.
6. **Pure crates stay safe.** `lib/` crates avoid `unsafe`; where one
   needs it, the crate says so at the top.
