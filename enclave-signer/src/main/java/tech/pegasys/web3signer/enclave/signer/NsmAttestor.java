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
package tech.pegasys.web3signer.enclave.signer;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

/**
 * Attestation documents from the AWS Nitro Security Module: {@code ioctl} on {@code /dev/nsm} with
 * a CBOR request, through FFM.
 */
public final class NsmAttestor implements Attestor {
  private static final String DEVICE = "/dev/nsm";
  private static final int O_RDWR_CLOEXEC = 0x80002;

  /** {@code _IOWR(0x0A, 0, struct { iovec request; iovec response; })}. */
  private static final long NSM_IOCTL_REQUEST = 0xC0200A00L;

  private static final int MAX_REQUEST_SIZE = 0x1000;
  private static final int RESPONSE_SIZE = 0x3000;

  private static final StructLayout CAPTURE = Linker.Option.captureStateLayout();
  private static final VarHandle ERRNO =
      CAPTURE.varHandle(MemoryLayout.PathElement.groupElement("errno"));

  private final MethodHandle open;
  private final MethodHandle ioctl;
  private final MethodHandle close;

  public NsmAttestor() {
    final Linker linker = Linker.nativeLinker();
    final Linker.Option errno = Linker.Option.captureCallState("errno");
    open =
        linker.downcallHandle(
            linker.defaultLookup().find("open").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT),
            errno,
            Linker.Option.firstVariadicArg(2));
    ioctl =
        linker.downcallHandle(
            linker.defaultLookup().find("ioctl").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, ADDRESS),
            errno,
            Linker.Option.firstVariadicArg(2));
    close =
        linker.downcallHandle(
            linker.defaultLookup().find("close").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT),
            errno);
  }

  @Override
  public byte[] attest(final byte[] publicKeySpki, final byte[] nonce) throws AttestationException {
    final byte[] request =
        NsmCbor.attestationRequest(null, nonce.length == 0 ? null : nonce, publicKeySpki);
    if (request.length > MAX_REQUEST_SIZE) {
      throw new AttestationException("NSM request too large");
    }
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment capture = arena.allocate(CAPTURE);
      final int fd = (int) open.invokeExact(capture, arena.allocateFrom(DEVICE), O_RDWR_CLOEXEC);
      if (fd < 0) {
        throw new AttestationException("open " + DEVICE + " failed, errno " + errno(capture));
      }
      try {
        final MemorySegment requestSegment = arena.allocate(request.length, 8);
        MemorySegment.copy(request, 0, requestSegment, JAVA_BYTE, 0, request.length);
        final MemorySegment response = arena.allocate(RESPONSE_SIZE, 8);
        final MemorySegment message = arena.allocate(32, 8);
        message.set(ADDRESS, 0, requestSegment);
        message.set(JAVA_LONG, 8, request.length);
        message.set(ADDRESS, 16, response);
        message.set(JAVA_LONG, 24, RESPONSE_SIZE);
        final int rc = (int) ioctl.invokeExact(capture, fd, NSM_IOCTL_REQUEST, message);
        if (rc != 0) {
          throw new AttestationException("NSM ioctl failed, errno " + errno(capture));
        }
        final long length = message.get(JAVA_LONG, 24);
        if (length <= 0 || length > RESPONSE_SIZE) {
          throw new AttestationException("NSM response length " + length);
        }
        return NsmCbor.attestationDocument(response.asSlice(0, length).toArray(JAVA_BYTE));
      } finally {
        final int ignored = (int) close.invokeExact(capture, fd);
      }
    } catch (final AttestationException e) {
      throw e;
    } catch (final NsmCbor.NsmException e) {
      throw new AttestationException(e.getMessage());
    } catch (final Throwable t) {
      throw new AttestationException("NSM call failed: " + t.getClass().getName());
    }
  }

  private static int errno(final MemorySegment capture) {
    return (int) ERRNO.get(capture, 0L);
  }
}
