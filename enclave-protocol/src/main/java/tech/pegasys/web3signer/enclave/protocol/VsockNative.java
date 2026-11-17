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
package tech.pegasys.web3signer.enclave.protocol;

import static java.lang.foreign.ValueLayout.ADDRESS;
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
import java.util.Locale;

/**
 * libc socket calls for AF_VSOCK through FFM. Every handle captures {@code errno}. No handle uses
 * {@code Linker.Option.critical}: a critical call would block garbage collection while a thread
 * waits in {@code read}.
 */
final class VsockNative {
  static final int AF_VSOCK = 40;
  static final int SOCK_STREAM = 1;
  static final int SOL_SOCKET = 1;
  static final int SO_RCVTIMEO = 20;
  static final int SO_SNDTIMEO = 21;
  static final int SHUT_RDWR = 2;
  static final int SOCKADDR_VM_SIZE = 16;

  static final int EINTR = 4;
  static final int EAGAIN = 11;
  static final int ENETUNREACH = 101;
  static final int ECONNRESET = 104;
  static final int ENOTCONN = 107;
  static final int ETIMEDOUT = 110;

  static final StructLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
  private static final VarHandle ERRNO =
      CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("errno"));

  private VsockNative() {}

  /** An {@link IOException} that carries the {@code errno} of the failed call. */
  static final class ErrnoException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int errno;

    ErrnoException(final String call, final int errno) {
      super(call + " failed with errno " + errno);
      this.errno = errno;
    }

    int errno() {
      return errno;
    }
  }

  /** Created on first use, so a TCP-only process never links libc symbols. */
  static final class Handles {
    static final MethodHandle SOCKET;
    static final MethodHandle BIND;
    static final MethodHandle LISTEN;
    static final MethodHandle ACCEPT;
    static final MethodHandle CONNECT;
    static final MethodHandle READ;
    static final MethodHandle WRITE;
    static final MethodHandle CLOSE;
    static final MethodHandle SHUTDOWN;
    static final MethodHandle SETSOCKOPT;

    static {
      SOCKET = libc("socket", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
      BIND = libc("bind", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
      LISTEN = libc("listen", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT));
      ACCEPT = libc("accept", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, ADDRESS));
      CONNECT = libc("connect", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
      READ = libc("read", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG));
      WRITE = libc("write", FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG));
      CLOSE = libc("close", FunctionDescriptor.of(JAVA_INT, JAVA_INT));
      SHUTDOWN = libc("shutdown", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT));
      SETSOCKOPT =
          libc(
              "setsockopt",
              FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT));
    }

    private static MethodHandle libc(final String name, final FunctionDescriptor descriptor) {
      final Linker linker = Linker.nativeLinker();
      return linker.downcallHandle(
          linker.defaultLookup().find(name).orElseThrow(),
          descriptor,
          Linker.Option.captureCallState("errno"));
    }

    private Handles() {}
  }

  static int errno(final MemorySegment capture) {
    return (int) ERRNO.get(capture, 0L);
  }

  static MemorySegment allocateCapture(final Arena arena) {
    return arena.allocate(CAPTURE_LAYOUT);
  }

  /** {@code struct sockaddr_vm}: family u16 at 0, port u32 at 4, cid u32 at 8, native order. */
  static MemorySegment sockaddrVm(final Arena arena, final int cid, final int port) {
    final MemorySegment address = arena.allocate(SOCKADDR_VM_SIZE, 4);
    address.set(JAVA_SHORT, 0, (short) AF_VSOCK);
    address.set(JAVA_INT, 4, port);
    address.set(JAVA_INT, 8, cid);
    return address;
  }

  /** Fails with a clear message off Linux, before any libc handle is created. */
  static void requireLinux() {
    final String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (!os.startsWith("linux")) {
      throw new UnsupportedOperationException(
          "vsock: addresses are only supported on Linux, not on " + os);
    }
  }

  static int socket() throws IOException {
    requireLinux();
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment capture = allocateCapture(arena);
      final int fd = (int) Handles.SOCKET.invokeExact(capture, AF_VSOCK, SOCK_STREAM, 0);
      if (fd < 0) {
        throw new ErrnoException("socket(AF_VSOCK)", errno(capture));
      }
      return fd;
    } catch (final IOException | RuntimeException e) {
      throw e;
    } catch (final Throwable t) {
      throw new IOException(t);
    }
  }

  /** Sets SO_RCVTIMEO and SO_SNDTIMEO. 0 means no timeout. */
  static void setTimeouts(final int fd, final int timeoutMillis) throws IOException {
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment capture = allocateCapture(arena);
      final MemorySegment timeval = arena.allocate(16, 8);
      timeval.set(JAVA_LONG, 0, timeoutMillis / 1000);
      timeval.set(JAVA_LONG, 8, (timeoutMillis % 1000) * 1000L);
      for (final int option : new int[] {SO_RCVTIMEO, SO_SNDTIMEO}) {
        final int rc =
            (int) Handles.SETSOCKOPT.invokeExact(capture, fd, SOL_SOCKET, option, timeval, 16);
        if (rc != 0) {
          throw new ErrnoException("setsockopt", errno(capture));
        }
      }
    } catch (final IOException | RuntimeException e) {
      throw e;
    } catch (final Throwable t) {
      throw new IOException(t);
    }
  }

  /** Best effort; callers may ignore the result. Returns the result of shutdown(2), or -1. */
  static int shutdownQuietly(final int fd) {
    try (Arena arena = Arena.ofConfined()) {
      return (int) Handles.SHUTDOWN.invokeExact(allocateCapture(arena), fd, SHUT_RDWR);
    } catch (final Throwable t) {
      return -1;
    }
  }

  /** Best effort; callers may ignore the result. Returns the result of close(2), or -1. */
  static int closeQuietly(final int fd) {
    try (Arena arena = Arena.ofConfined()) {
      return (int) Handles.CLOSE.invokeExact(allocateCapture(arena), fd);
    } catch (final Throwable t) {
      return -1;
    }
  }
}
