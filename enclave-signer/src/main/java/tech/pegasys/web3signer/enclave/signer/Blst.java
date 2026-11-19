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
import static java.lang.foreign.ValueLayout.JAVA_BOOLEAN;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * BLS12-381 through the blst C API (FFM). Proof-of-possession ciphersuite, public keys in G1. Every
 * argument is a native segment; scratch segments belong to one thread ({@link Scratch}).
 */
public final class Blst {
  public static final int SCALAR_SIZE = 32;
  public static final int P1_SIZE = 144;
  public static final int P2_SIZE = 288;
  private static final long ALIGNMENT = 8;
  private static final byte[] DST_BYTES =
      "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".getBytes(StandardCharsets.US_ASCII);

  private final MethodHandle scalarFromBendian;
  private final MethodHandle skCheck;
  private final MethodHandle skToPkInG1;
  private final MethodHandle p1Compress;
  private final MethodHandle hashToG2;
  private final MethodHandle signPkInG1;
  private final MethodHandle p2Compress;
  private final MemorySegment dst;

  public Blst(final Path library) {
    final SymbolLookup lookup = SymbolLookup.libraryLookup(library, Arena.global());
    scalarFromBendian =
        bind(lookup, "blst_scalar_from_bendian", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS));
    skCheck = bind(lookup, "blst_sk_check", FunctionDescriptor.of(JAVA_BOOLEAN, ADDRESS));
    skToPkInG1 = bind(lookup, "blst_sk_to_pk_in_g1", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS));
    p1Compress = bind(lookup, "blst_p1_compress", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS));
    hashToG2 =
        bind(
            lookup,
            "blst_hash_to_g2",
            FunctionDescriptor.ofVoid(
                ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
    signPkInG1 =
        bind(lookup, "blst_sign_pk_in_g1", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS));
    p2Compress = bind(lookup, "blst_p2_compress", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS));
    dst = Arena.global().allocate(DST_BYTES.length, ALIGNMENT);
    MemorySegment.copy(DST_BYTES, 0, dst, JAVA_BYTE, 0, DST_BYTES.length);
  }

  private static MethodHandle bind(
      final SymbolLookup lookup, final String name, final FunctionDescriptor descriptor) {
    return Linker.nativeLinker()
        .downcallHandle(
            lookup
                .find(name)
                .orElseThrow(() -> new IllegalStateException("blst symbol missing: " + name)),
            descriptor);
  }

  /** Native scratch memory of one thread. Allocation-free signing. */
  public static final class Scratch {
    final MemorySegment message;
    final MemorySegment hash;
    final MemorySegment signature;
    final MemorySegment compressedSignature;
    final MemorySegment p1;
    final MemorySegment compressedPublicKey;
    final MemorySegment bigEndian;

    public Scratch(final Arena arena) {
      message = arena.allocate(Protocol.MAX_MESSAGE_SIZE, ALIGNMENT);
      hash = arena.allocate(P2_SIZE, ALIGNMENT);
      signature = arena.allocate(P2_SIZE, ALIGNMENT);
      compressedSignature = arena.allocate(Protocol.SIGNATURE_SIZE, ALIGNMENT);
      p1 = arena.allocate(P1_SIZE, ALIGNMENT);
      compressedPublicKey = arena.allocate(Protocol.PUBLIC_KEY_SIZE, ALIGNMENT);
      bigEndian = arena.allocate(SCALAR_SIZE, ALIGNMENT);
    }

    /** Zeroes the memory that held secret material. */
    public void wipe() {
      bigEndian.fill((byte) 0);
    }
  }

  public static MemorySegment allocateScalar(final Arena arena) {
    return arena.allocate(SCALAR_SIZE, ALIGNMENT);
  }

  /**
   * Converts a 32-byte big-endian secret into a {@code blst_scalar}. The bytes pass through the
   * scratch, which is zeroed afterwards.
   */
  public void scalarFromBigEndian(
      final Scratch scratch, final byte[] secret, final int offset, final MemorySegment scalar) {
    MemorySegment.copy(secret, offset, scratch.bigEndian, JAVA_BYTE, 0, SCALAR_SIZE);
    try {
      scalarFromBendian.invokeExact(scalar, scratch.bigEndian);
    } catch (final Throwable t) {
      throw new IllegalStateException("blst_scalar_from_bendian failed", t);
    } finally {
      scratch.wipe();
    }
  }

  /** True when the scalar is a valid secret key: not zero and below the group order. */
  public boolean isValidSecretKey(final MemorySegment scalar) {
    try {
      return (boolean) skCheck.invokeExact(scalar);
    } catch (final Throwable t) {
      throw new IllegalStateException("blst_sk_check failed", t);
    }
  }

  /** Writes the 48-byte compressed public key of {@code scalar} to {@code out[offset..]}. */
  public void publicKey(
      final Scratch scratch, final MemorySegment scalar, final byte[] out, final int offset) {
    try {
      skToPkInG1.invokeExact(scratch.p1, scalar);
      p1Compress.invokeExact(scratch.compressedPublicKey, scratch.p1);
    } catch (final Throwable t) {
      throw new IllegalStateException("blst public key derivation failed", t);
    }
    MemorySegment.copy(
        scratch.compressedPublicKey, JAVA_BYTE, 0, out, offset, Protocol.PUBLIC_KEY_SIZE);
  }

  /**
   * Signs {@code message[messageOffset..messageOffset + messageLength)} and writes the 96-byte
   * compressed signature to {@code out[outOffset..]}.
   */
  public void sign(
      final Scratch scratch,
      final MemorySegment scalar,
      final byte[] message,
      final int messageOffset,
      final int messageLength,
      final byte[] out,
      final int outOffset) {
    MemorySegment.copy(message, messageOffset, scratch.message, JAVA_BYTE, 0, messageLength);
    try {
      hashToG2.invokeExact(
          scratch.hash,
          scratch.message,
          (long) messageLength,
          dst,
          (long) DST_BYTES.length,
          MemorySegment.NULL,
          0L);
      signPkInG1.invokeExact(scratch.signature, scratch.hash, scalar);
      p2Compress.invokeExact(scratch.compressedSignature, scratch.signature);
    } catch (final Throwable t) {
      throw new IllegalStateException("blst signing failed", t);
    }
    MemorySegment.copy(
        scratch.compressedSignature, JAVA_BYTE, 0, out, outOffset, Protocol.SIGNATURE_SIZE);
  }
}
