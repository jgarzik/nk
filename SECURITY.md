# Security

NK 0.0.1 is a research milestone, not a system to deploy. Read this before
running it anywhere that matters.

## What NK does not protect against

- **Drivers are fully trusted.** A loaded driver runs in kernel mode with
  access to all memory. NK checks that an image is well formed and that
  its imports resolve; it does not verify signatures or restrict what a
  driver does. Load only drivers you trust, in a virtual machine.
- **There is no user mode**, so there is no boundary between applications
  and the kernel to defend yet.
- **Known weaknesses** in the current memory layout are listed under
  "Known limits" in `doc/BOOT.md`: for example, the direct map is a
  writable alias of kernel text, and stack-protector cookies are seeded
  from the CPU cycle counter rather than a real random source.

Checks such as pool guard bytes and bad-free detection exist to catch
bugs during development. They are not security mitigations.

## Reporting a problem

For an ordinary bug, including a crash or a wrong result from a driver
routine, open a public issue.

If you believe you have found something that should not be discussed in
public first, use GitHub's private vulnerability reporting on this
repository ("Report a vulnerability" under the Security tab). Expect a
reply, but not a service-level commitment: this is an early-stage project.
