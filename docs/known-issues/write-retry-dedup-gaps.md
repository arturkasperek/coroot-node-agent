# Retried writes still counted twice on some paths

**Status:** open (the common plain `write`/`writev`/`sendto`/`sendmsg` path is
fixed). **Severity:** unknown, likely small.

## Background

The capture of outgoing bytes happens at syscall entry. A write that returns
`EAGAIN`, or fewer bytes than asked, is retried by the application with the same
bytes, so they were seen twice. One duplicated HTTP/2 HEADERS block corrupts the
HPACK dynamic table for the following requests. The fix (`write_replay`,
`last_write_map` and the `sys_exit_*` programs in `ebpf/l7/l7.c`, test
`TestHttp2WriteRetriedAfterIncompleteWriteIsNotDuplicated`) records the unsent
tail at syscall exit and skips it on the next write to the same address of the
same connection.

## What is not covered

1. **TLS plaintext (`SSL_write`).** An `SSL_write` that fails with `WANT_WRITE`
   is retried with the same buffer; the plaintext is captured at the inner
   syscall each time. There is no `SSL_write` exit uprobe, so there is no return
   value to check. The deduplication is skipped for `is_tls`.
2. **`sendmmsg`.** Several messages per syscall; `ret` is the number of messages.
   No exit program, no deduplication.
3. **Partial `writev`/`sendmsg`.** Only `ret == EAGAIN` (nothing sent) is
   handled; with `0 < ret < total` the retry starts in the middle of an iovec
   element, which the address comparison cannot express.
4. **Retries from another buffer.** The match is the buffer address (plus the
   iovec array address and length). An application that copies the data to a new
   buffer before retrying is not recognized.
5. **Retries after 30 s** (`WRITE_REPLAY_MAX_AGE_NS`) and writes to a connection
   that was closed and replaced on the same `(pid, fd)` in between.

## Ideas

- For TLS: add an `SSL_write` exit uprobe (Go: `crypto/tls.(*Conn).Write` return)
  and feed the same `write_replay` map.
- For the others: compute how many bytes were really sent from `ret` and walk
  the iovec to find the element and offset.
- Alternative design: do the whole capture at syscall exit (like reads),
  using the saved arguments and `ret` as the cap. Bigger change; the BPF
  programs are close to the 1M-instruction verifier limit: a change that
  inlines a loop or a counter into every syscall program fails to load with
  `argument list too long`, and the agent then runs with no capture at all.
  Put long logic in a global (non-inlined) function that takes only scalar or
  pointer-to-scalar arguments.

## Reproduce

The unit test above (`VM=1`, privileged Linux, see `ebpftracer/Makefile`) builds
an `EAGAIN` by filling a socket with tiny `SO_SNDBUF`/`SO_RCVBUF`. Copy it and
change the writer to `sendmmsg` or an `SSL_write` on a non-blocking socket.
