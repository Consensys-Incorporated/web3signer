/*
 * Copyright 2026 Consensys Incorporated.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.web3signer.enclave.transport;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Locale;

/**
 * AF_VSOCK stream sockets on Linux, through FFM: connect, listen, and blocking reads and writes.
 *
 * <p>One thread at a time uses a socket; {@code close} may come from any other. It shuts the socket
 * down at once, which wakes a thread blocked in a read or write on it, and the descriptor and
 * native memory are freed once the call running on the socket returns. A closed socket therefore
 * never reaches a descriptor number that the kernel has handed out again.
 */
final class Vsock {
  static final int ENETUNREACH = 101;

  private static final int AF_VSOCK = 40;
  private static final int SOCK_STREAM = 1;
  private static final int SOCK_CLOEXEC = 0x80000;
  private static final int SOL_SOCKET = 1;
  private static final int SO_RCVTIMEO = 20;
  private static final int SO_SNDTIMEO = 21;
  private static final int SHUT_RDWR = 2;
  private static final int SOCKADDR_VM_SIZE = 16;
  private static final int BACKLOG = 128;
  private static final int BUFFER_SIZE = 64 * 1024;

  private static final int EINTR = 4;
  private static final int EAGAIN = 11;
  private static final int ECONNRESET = 104;
  private static final int ENOTCONN = 107;

  /**
   * How often a blocked accept wakes to see whether the listener was closed. shutdown(2) on a
   * listening vsock socket fails with ENOTCONN and does not wake accept(2), and the descriptor is
   * closed only after accept returns, so accept runs with this receive timeout instead.
   */
  private static final int ACCEPT_WAKE_MILLIS = 200;

  private static final StructLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
  private static final VarHandle ERRNO =
      CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("errno"));

  private Vsock() {}

  /** An {@link IOException} that carries the {@code errno} of the failed call, and names it. */
  static final class ErrnoException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int errno;

    ErrnoException(final String call, final int errno) {
      super(call + " failed: " + describe(errno));
      this.errno = errno;
    }

    int errno() {
      return errno;
    }

    /** The errors a socket call on Linux is expected to meet, by name and meaning. */
    static String describe(final int errno) {
      final String name =
          switch (errno) {
            case 1 -> "EPERM (operation not permitted)";
            case 13 -> "EACCES (permission denied)";
            case 19 -> "ENODEV (no such device: is the vsock driver loaded?)";
            case 24 -> "EMFILE (too many open files)";
            case 32 -> "EPIPE (broken pipe)";
            case 97 -> "EAFNOSUPPORT (address family not supported: no vsock support)";
            case 98 -> "EADDRINUSE (address already in use)";
            case ENETUNREACH -> "ENETUNREACH (network unreachable: no vsock transport to that CID)";
            case ECONNRESET -> "ECONNRESET (connection reset by peer)";
            case ENOTCONN -> "ENOTCONN (not connected)";
            case 110 -> "ETIMEDOUT (connection timed out: is the enclave running?)";
            case 111 -> "ECONNREFUSED (connection refused: nothing listens on that port)";
            case 113 -> "EHOSTUNREACH (no route to host)";
            default -> null;
          };
      return name == null ? "errno " + errno : name + ", errno " + errno;
    }
  }

  /**
   * Connects to {@code cid:port}. Without an enclave at that CID the kernel gives up with {@code
   * ETIMEDOUT} after about 2 s.
   *
   * @param timeoutMillis read and write timeout; 0 waits forever
   */
  static Connection connect(final int cid, final int port, final int timeoutMillis)
      throws IOException {
    final int fd = socket();
    try (Arena call = Arena.ofConfined()) {
      final MemorySegment address = sockaddrVm(call, cid, port);
      invoke(
          "connect(vsock:" + Integer.toUnsignedString(cid) + ")",
          call.allocate(CAPTURE_LAYOUT),
          capture -> (int) Handles.CONNECT.invokeExact(capture, fd, address, SOCKADDR_VM_SIZE));
      setTimeouts(fd, timeoutMillis);
      return new VsockConnection(fd);
    } catch (final IOException | RuntimeException e) {
      closeQuietly(fd);
      throw e;
    }
  }

  /** Listens on {@code port} for any CID. */
  static Listener listen(final int port) throws IOException {
    final int fd = socket();
    try (Arena call = Arena.ofConfined()) {
      final MemorySegment capture = call.allocate(CAPTURE_LAYOUT);
      final MemorySegment address = sockaddrVm(call, (int) EnclaveAddress.VMADDR_CID_ANY, port);
      invoke(
          "bind(vsock:" + Integer.toUnsignedString(port) + ")",
          capture,
          c -> (int) Handles.BIND.invokeExact(c, fd, address, SOCKADDR_VM_SIZE));
      invoke("listen", capture, c -> (int) Handles.LISTEN.invokeExact(c, fd, BACKLOG));
      setTimeouts(fd, ACCEPT_WAKE_MILLIS);
      return new VsockListener(fd, port);
    } catch (final IOException | RuntimeException e) {
      closeQuietly(fd);
      throw e;
    }
  }

  /** A connection on an already connected stream socket. For tests on a local socket pair. */
  static Connection wrap(final int fd) {
    return new VsockConnection(fd);
  }

  // ------------------------------------------------------------------ native calls

  /** One libc call; its errno lands in {@code capture}. */
  @FunctionalInterface
  private interface NativeCall {
    long invoke(MemorySegment capture) throws Throwable;
  }

  /**
   * Runs a libc call, again after {@code EINTR}.
   *
   * @return its result, never negative
   * @throws ErrnoException when it fails with another errno
   */
  private static long invoke(final String name, final MemorySegment capture, final NativeCall call)
      throws IOException {
    while (true) {
      final long result;
      try {
        result = call.invoke(capture);
      } catch (final RuntimeException | Error e) {
        throw e;
      } catch (final Throwable t) {
        throw new IOException(name + " failed", t);
      }
      if (result >= 0) {
        return result;
      }
      final int errno = (int) ERRNO.get(capture, 0L);
      if (errno != EINTR) {
        throw new ErrnoException(name, errno);
      }
    }
  }

  // ------------------------------------------------------------------ descriptor lifetime

  /** A descriptor used by one call at a time and closed from any thread. */
  private static final class Descriptor {
    private final int fd;
    private final Arena arena;
    private boolean inCall;
    private boolean closed;

    /**
     * @param arena memory used with the descriptor; freed together with it
     */
    Descriptor(final int fd, final Arena arena) {
      this.fd = fd;
      this.arena = arena;
    }

    /** Marks the start of a call. Pair with {@link #release()} in a finally. */
    synchronized int acquire() throws SocketException {
      if (closed) {
        throw new SocketException("Socket closed");
      }
      if (inCall) {
        throw new IllegalStateException("vsock socket used by two threads at once");
      }
      inCall = true;
      return fd;
    }

    synchronized void release() {
      inCall = false;
      if (closed) {
        free();
      }
    }

    synchronized boolean isClosed() {
      return closed;
    }

    synchronized boolean inCall() {
      return inCall;
    }

    synchronized void close() {
      if (closed) {
        return;
      }
      closed = true;
      shutdownQuietly(fd);
      if (!inCall) {
        free();
      }
    }

    private void free() {
      closeQuietly(fd);
      arena.close();
    }
  }

  // ------------------------------------------------------------------ connection

  static final class VsockConnection implements Connection {
    private final Arena arena = Arena.ofShared();
    private final MemorySegment capture = arena.allocate(CAPTURE_LAYOUT);
    private final MemorySegment in = arena.allocate(BUFFER_SIZE, 8);
    private final MemorySegment out = arena.allocate(BUFFER_SIZE, 8);
    private final Descriptor descriptor;
    private int inPosition;
    private int inLimit;

    VsockConnection(final int fd) {
      this.descriptor = new Descriptor(fd, arena);
    }

    @Override
    public int read(final byte[] buffer, final int offset, final int length) throws IOException {
      if (length == 0) {
        return 0;
      }
      final int fd = descriptor.acquire();
      try {
        if (inPosition == inLimit && !fill(fd)) {
          return -1;
        }
        final int n = Math.min(length, inLimit - inPosition);
        MemorySegment.copy(in, JAVA_BYTE, inPosition, buffer, offset, n);
        inPosition += n;
        return n;
      } finally {
        descriptor.release();
      }
    }

    /** Reads into the native buffer. Returns false at the end of the stream. */
    private boolean fill(final int fd) throws IOException {
      final long n;
      try {
        n =
            invoke(
                "read",
                capture,
                c -> (long) Handles.READ.invokeExact(c, fd, in, (long) BUFFER_SIZE));
      } catch (final ErrnoException e) {
        return switch (e.errno()) {
          case EAGAIN -> throw new SocketTimeoutException("vsock read timed out");
          case ECONNRESET, ENOTCONN -> false;
          default -> throw e;
        };
      }
      inPosition = 0;
      inLimit = (int) n;
      return n > 0;
    }

    @Override
    public void write(final byte[] buffer, final int offset, final int length) throws IOException {
      final int fd = descriptor.acquire();
      try {
        int done = 0;
        while (done < length) {
          final int chunk = Math.min(length - done, BUFFER_SIZE);
          MemorySegment.copy(buffer, offset + done, out, JAVA_BYTE, 0, chunk);
          long sent = 0;
          while (sent < chunk) {
            sent += writeSome(fd, out.asSlice(sent), chunk - sent);
          }
          done += chunk;
        }
      } finally {
        descriptor.release();
      }
    }

    private long writeSome(final int fd, final MemorySegment from, final long size)
        throws IOException {
      try {
        return invoke("write", capture, c -> (long) Handles.WRITE.invokeExact(c, fd, from, size));
      } catch (final ErrnoException e) {
        if (e.errno() == EAGAIN) {
          throw new SocketTimeoutException("vsock write timed out");
        }
        throw e;
      }
    }

    @Override
    public void close() {
      descriptor.close();
    }

    /** For tests: once true, a close shuts the socket down under the call instead of freeing it. */
    boolean inCall() {
      return descriptor.inCall();
    }
  }

  // ------------------------------------------------------------------ listener

  static final class VsockListener implements Listener {
    private final Arena arena = Arena.ofShared();
    private final MemorySegment capture = arena.allocate(CAPTURE_LAYOUT);
    private final Descriptor descriptor;
    private final EnclaveAddress address;

    VsockListener(final int fd, final int port) {
      this.descriptor = new Descriptor(fd, arena);
      this.address =
          EnclaveAddress.vsock(EnclaveAddress.VMADDR_CID_ANY, Integer.toUnsignedLong(port));
    }

    @Override
    public Connection accept() throws IOException {
      while (true) {
        final int fd = descriptor.acquire(); // throws once the listener is closed
        try {
          final int connection =
              (int)
                  invoke(
                      "accept4",
                      capture,
                      c ->
                          (int)
                              Handles.ACCEPT4.invokeExact(
                                  c, fd, MemorySegment.NULL, MemorySegment.NULL, SOCK_CLOEXEC));
          return accepted(connection);
        } catch (final ErrnoException e) {
          if (descriptor.isClosed()) {
            throw new SocketException("Listener closed");
          }
          if (e.errno() != EAGAIN) {
            throw e;
          }
        } finally {
          descriptor.release();
        }
      }
    }

    /** For tests: true while accept is in a call, so a close ends it with "Listener closed". */
    boolean inCall() {
      return descriptor.inCall();
    }

    /** Clears the listener's wake-up timeout in case the accepted socket inherited it. */
    private static Connection accepted(final int fd) throws IOException {
      try {
        setTimeouts(fd, 0);
      } catch (final IOException | RuntimeException e) {
        closeQuietly(fd);
        throw e;
      }
      return new VsockConnection(fd);
    }

    @Override
    public EnclaveAddress address() {
      return address;
    }

    @Override
    public void close() {
      descriptor.close();
    }
  }

  // ------------------------------------------------------------------ libc

  /**
   * libc socket calls, created on first use so that a TCP-only process never links them. Every
   * handle captures {@code errno}. None uses {@code Linker.Option.critical}: a critical call would
   * block garbage collection while a thread waits in {@code read}.
   */
  private static final class Handles {
    static final MethodHandle SOCKET =
        libc("socket", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
    static final MethodHandle BIND =
        libc("bind", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
    static final MethodHandle LISTEN =
        libc("listen", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT));
    static final MethodHandle ACCEPT4 =
        libc("accept4", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
    static final MethodHandle CONNECT =
        libc("connect", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
    static final MethodHandle READ =
        libc("read", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG));
    static final MethodHandle WRITE =
        libc("write", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG));
    static final MethodHandle CLOSE = libc("close", FunctionDescriptor.of(JAVA_INT, JAVA_INT));
    static final MethodHandle SHUTDOWN =
        libc("shutdown", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT));
    static final MethodHandle SETSOCKOPT =
        libc(
            "setsockopt",
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));

    private static MethodHandle libc(final String name, final FunctionDescriptor descriptor) {
      final Linker linker = Linker.nativeLinker();
      return linker.downcallHandle(
          linker.defaultLookup().find(name).orElseThrow(),
          descriptor,
          Linker.Option.captureCallState("errno"));
    }

    private Handles() {}
  }

  /** {@code struct sockaddr_vm}: family u16 at 0, port u32 at 4, cid u32 at 8, native order. */
  private static MemorySegment sockaddrVm(final Arena arena, final int cid, final int port) {
    final MemorySegment address = arena.allocate(SOCKADDR_VM_SIZE, 4);
    address.set(JAVA_SHORT, 0, (short) AF_VSOCK);
    address.set(JAVA_INT, 4, port);
    address.set(JAVA_INT, 8, cid);
    return address;
  }

  private static int socket() throws IOException {
    // fails with a clear message off 64-bit Linux on x86 or ARM, before any libc handle is created;
    // the socket option numbers and timeval layout below are only right there
    final String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    final String arch = System.getProperty("os.arch", "");
    if (!os.startsWith("linux") || !(arch.equals("amd64") || arch.equals("aarch64"))) {
      throw new UnsupportedOperationException(
          "vsock: addresses are only supported on Linux on amd64 and aarch64, not on "
              + os
              + " "
              + arch);
    }
    try (Arena arena = Arena.ofConfined()) {
      return (int)
          invoke(
              "socket(AF_VSOCK)",
              arena.allocate(CAPTURE_LAYOUT),
              c -> (int) Handles.SOCKET.invokeExact(c, AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
    }
  }

  /** Sets SO_RCVTIMEO and SO_SNDTIMEO. 0 means no timeout. */
  static void setTimeouts(final int fd, final int timeoutMillis) throws IOException {
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment capture = arena.allocate(CAPTURE_LAYOUT);
      final MemorySegment timeval = arena.allocate(16, 8);
      timeval.set(JAVA_LONG, 0, timeoutMillis / 1000);
      timeval.set(JAVA_LONG, 8, (timeoutMillis % 1000) * 1000L);
      for (final int option : new int[] {SO_RCVTIMEO, SO_SNDTIMEO}) {
        invoke(
            "setsockopt",
            capture,
            c -> (int) Handles.SETSOCKOPT.invokeExact(c, fd, SOL_SOCKET, option, timeval, 16));
      }
    }
  }

  /**
   * Best effort. Returns the result of shutdown(2), or -1. Not repeated after {@code EINTR}: the
   * socket is going away either way.
   */
  private static int shutdownQuietly(final int fd) {
    try (Arena arena = Arena.ofConfined()) {
      return (int) Handles.SHUTDOWN.invokeExact(arena.allocate(CAPTURE_LAYOUT), fd, SHUT_RDWR);
    } catch (final Throwable t) {
      return -1;
    }
  }

  /**
   * Best effort. Returns the result of close(2), or -1. Never repeated: on Linux the descriptor is
   * released even when close fails with {@code EINTR}.
   */
  private static int closeQuietly(final int fd) {
    try (Arena arena = Arena.ofConfined()) {
      return (int) Handles.CLOSE.invokeExact(arena.allocate(CAPTURE_LAYOUT), fd);
    } catch (final Throwable t) {
      return -1;
    }
  }
}
