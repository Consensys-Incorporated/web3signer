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

import static tech.pegasys.web3signer.enclave.protocol.Protocol.BOOT_ID_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_BLOB_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_ERROR_MESSAGE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_EVIDENCE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_LOAD_KEYS;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_NONCE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_PUBLIC_KEYS_PAGE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_RELEASE_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_VERSION_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.PUBLIC_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SEALED_CIPHERTEXT_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SEALED_NONCE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SIGNATURE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SIGNING_ROOT_SIZE;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

/**
 * SSZ bodies of the protocol messages, and the records they decode to. Every message has an {@code
 * encode} and a {@code decode} method over a whole body. Encoders throw {@link
 * IllegalArgumentException} on values outside the message's limits; decoders throw {@link
 * IOException} on a malformed body.
 */
public final class Messages {
  private static final byte[] EMPTY = new byte[0];

  private Messages() {}

  // ------------------------------------------------------------------ records

  /**
   * Answer to {@code STATUS}.
   *
   * @param protocolVersion protocol version of the signer
   * @param platform {@link Protocol#PLATFORM_DEV} or {@link Protocol#PLATFORM_AWS_NITRO}
   * @param cpus processors available to the signer
   * @param keyCount number of loaded keys
   * @param bootId 16 random bytes chosen at signer start, as hex
   * @param version implementation version of the signer, printable ASCII
   */
  public record Status(
      int protocolVersion, int platform, int cpus, long keyCount, String bootId, String version) {

    public String platformName() {
      return Protocol.platformName(platform);
    }
  }

  /** A {@code GET_PUBLIC_KEYS} request: up to {@code limit} keys from position {@code offset}. */
  public record PublicKeysRequest(long offset, int limit) {}

  /** A {@code SIGN} request. */
  @SuppressWarnings("ArrayRecordComponent")
  public record SignRequest(byte[] pubKey, byte[] signingRoot) {}

  /**
   * Answer to {@code GET_EVIDENCE}.
   *
   * @param evidenceType {@link Protocol#EVIDENCE_AWS_NITRO} or {@link Protocol#EVIDENCE_DEV}
   * @param releaseKey DER SubjectPublicKeyInfo of the RSA key the data key is released to
   * @param evidence the platform's evidence, binding the release key and the nonce
   */
  @SuppressWarnings("ArrayRecordComponent")
  public record Evidence(int evidenceType, byte[] releaseKey, byte[] evidence) {}

  /** An {@code UNWRAP_DEK} request. */
  @SuppressWarnings("ArrayRecordComponent")
  public record UnwrapDekRequest(int format, byte[] blob) {}

  /**
   * One entry of {@code LOAD_KEYS}: a BLS secret encrypted with AES-256-GCM under the data key.
   *
   * @param pubKey compressed BLS public key, 48 bytes; also the GCM additional data
   * @param nonce GCM nonce, 12 bytes
   * @param ciphertext 32 bytes of ciphertext followed by the 16-byte tag
   */
  @SuppressWarnings("ArrayRecordComponent")
  public record SealedKey(byte[] pubKey, byte[] nonce, byte[] ciphertext) {

    public SealedKey {
      if (pubKey.length != PUBLIC_KEY_SIZE
          || nonce.length != SEALED_NONCE_SIZE
          || ciphertext.length != SEALED_CIPHERTEXT_SIZE) {
        throw new IllegalArgumentException("Sealed key has wrong field sizes");
      }
    }
  }

  /**
   * Answer to {@code LOAD_KEYS}.
   *
   * @param loaded entries added to the key set
   * @param duplicates entries whose public key was already loaded
   * @param rejected entries that failed authentication or the key checks
   */
  public record KeyLoadCounts(long loaded, long duplicates, long rejected) {
    public static final KeyLoadCounts EMPTY = new KeyLoadCounts(0, 0, 0);

    public KeyLoadCounts plus(final KeyLoadCounts other) {
      return new KeyLoadCounts(
          loaded + other.loaded, duplicates + other.duplicates, rejected + other.rejected);
    }
  }

  // ------------------------------------------------------------------ STATUS

  /** The empty body of a {@code STATUS} request. */
  public static byte[] encodeStatusRequest() {
    return EMPTY;
  }

  public static void decodeStatusRequest(final byte[] body) throws IOException {
    requireEmpty(body, "STATUS request");
  }

  /**
   * {@code Status}; {@code cpus} is capped at 65,535 and {@code version} is reduced to printable
   * ASCII and 256 bytes.
   */
  public static byte[] encodeStatus(
      final int platform,
      final long cpus,
      final long keyCount,
      final byte[] bootId,
      final String version) {
    return Ssz.writeContainer()
        .uint8(Protocol.VERSION)
        .uint8(platform)
        .uint16(Math.clamp(cpus, 0, 0xffff))
        .uint32(keyCount)
        .vector(bootId, BOOT_ID_SIZE)
        .byteList(printableAscii(version, MAX_VERSION_SIZE), MAX_VERSION_SIZE)
        .toBytes();
  }

  /**
   * Decodes a {@code Status}. The protocol version is read first, so that a signer of another
   * version is reported as such even when the rest of its answer has another layout.
   *
   * @throws UnsupportedProtocolVersionException when the signer speaks another protocol version
   */
  public static Status decodeStatus(final byte[] body) throws IOException {
    return Ssz.readContainer(
        body,
        "STATUS response",
        in -> {
          final int protocolVersion = in.uint8();
          if (protocolVersion != Protocol.VERSION) {
            throw new UnsupportedProtocolVersionException(protocolVersion);
          }
          return new Status(
              protocolVersion,
              in.uint8(),
              in.uint16(),
              in.uint32(),
              HexFormat.of().formatHex(in.vector(BOOT_ID_SIZE)),
              printableAscii(in.byteList(MAX_VERSION_SIZE)));
        });
  }

  // ------------------------------------------------------------------ GET_PUBLIC_KEYS

  public static byte[] encodePublicKeysRequest(final PublicKeysRequest request) {
    if (request.limit() < 1 || request.limit() > MAX_PUBLIC_KEYS_PAGE) {
      throw new IllegalArgumentException("Invalid page request: " + request);
    }
    return Ssz.writeContainer().uint32(request.offset()).uint32(request.limit()).toBytes();
  }

  public static PublicKeysRequest decodePublicKeysRequest(final byte[] body) throws IOException {
    return Ssz.readContainer(
        body,
        "GET_PUBLIC_KEYS request",
        in -> {
          final long offset = in.uint32();
          final long limit = in.uint32();
          in.checkBody(limit >= 1 && limit <= MAX_PUBLIC_KEYS_PAGE, "limit out of range");
          return new PublicKeysRequest(offset, (int) limit);
        });
  }

  /** A {@code List[Bytes48, 16384]}; a page shorter than asked is the last. */
  public static byte[] encodePublicKeys(final List<byte[]> publicKeys) {
    return Ssz.writeList(
        publicKeys, MAX_PUBLIC_KEYS_PAGE, (out, key) -> out.vector(key, PUBLIC_KEY_SIZE));
  }

  public static List<byte[]> decodePublicKeys(final byte[] body) throws IOException {
    return Ssz.readList(
        body, MAX_PUBLIC_KEYS_PAGE, "GET_PUBLIC_KEYS response", in -> in.vector(PUBLIC_KEY_SIZE));
  }

  // ------------------------------------------------------------------ SIGN

  /**
   * {@code SignRequest}; throws {@link IllegalArgumentException} on a key or root of wrong size.
   */
  public static byte[] encodeSignRequest(final SignRequest request) {
    return Ssz.writeContainer()
        .vector(request.pubKey(), PUBLIC_KEY_SIZE)
        .vector(request.signingRoot(), SIGNING_ROOT_SIZE)
        .toBytes();
  }

  public static SignRequest decodeSignRequest(final byte[] body) throws IOException {
    return Ssz.readContainer(
        body,
        "SIGN request",
        in -> new SignRequest(in.vector(PUBLIC_KEY_SIZE), in.vector(SIGNING_ROOT_SIZE)));
  }

  /** The {@code SIGN} answer: the 96-byte compressed signature. */
  public static byte[] encodeSignature(final byte[] signature) {
    return Ssz.writeContainer().vector(signature, SIGNATURE_SIZE).toBytes();
  }

  public static byte[] decodeSignature(final byte[] body) throws IOException {
    return Ssz.readContainer(body, "SIGN response", in -> in.vector(SIGNATURE_SIZE));
  }

  // ------------------------------------------------------------------ GET_EVIDENCE

  /** The nonce, a {@code List[Byte, 64]}, is the whole body. */
  public static byte[] encodeNonce(final byte[] nonce) {
    return Ssz.writeByteList(nonce, MAX_NONCE_SIZE);
  }

  public static byte[] decodeNonce(final byte[] body) throws IOException {
    return Ssz.readByteList(body, MAX_NONCE_SIZE, "GET_EVIDENCE request");
  }

  public static byte[] encodeEvidence(final Evidence evidence) {
    return Ssz.writeContainer()
        .uint8(evidence.evidenceType())
        .byteList(evidence.releaseKey(), MAX_RELEASE_KEY_SIZE)
        .byteList(evidence.evidence(), MAX_EVIDENCE_SIZE)
        .toBytes();
  }

  public static Evidence decodeEvidence(final byte[] body) throws IOException {
    return Ssz.readContainer(
        body,
        "GET_EVIDENCE response",
        in ->
            new Evidence(
                in.uint8(), in.byteList(MAX_RELEASE_KEY_SIZE), in.byteList(MAX_EVIDENCE_SIZE)));
  }

  // ------------------------------------------------------------------ UNWRAP_DEK

  public static byte[] encodeUnwrapDekRequest(final UnwrapDekRequest request) {
    return Ssz.writeContainer()
        .uint8(request.format())
        .byteList(request.blob(), MAX_BLOB_SIZE)
        .toBytes();
  }

  public static UnwrapDekRequest decodeUnwrapDekRequest(final byte[] body) throws IOException {
    return Ssz.readContainer(
        body,
        "UNWRAP_DEK request",
        in -> new UnwrapDekRequest(in.uint8(), in.byteList(MAX_BLOB_SIZE)));
  }

  /** The empty body of an {@code UNWRAP_DEK} answer. */
  public static byte[] encodeUnwrapDekResponse() {
    return EMPTY;
  }

  public static void decodeUnwrapDekResponse(final byte[] body) throws IOException {
    requireEmpty(body, "UNWRAP_DEK response");
  }

  // ------------------------------------------------------------------ LOAD_KEYS

  /** A {@code List[SealedKey, 4096]} with 1 to 4,096 entries. */
  public static byte[] encodeSealedKeys(final List<SealedKey> keys) {
    if (keys.isEmpty()) {
      throw new IllegalArgumentException("LOAD_KEYS takes at least one entry");
    }
    return Ssz.writeList(
        keys,
        MAX_LOAD_KEYS,
        (out, key) ->
            out.vector(key.pubKey(), PUBLIC_KEY_SIZE)
                .vector(key.nonce(), SEALED_NONCE_SIZE)
                .vector(key.ciphertext(), SEALED_CIPHERTEXT_SIZE));
  }

  public static List<SealedKey> decodeSealedKeys(final byte[] body) throws IOException {
    final List<SealedKey> keys =
        Ssz.readList(
            body,
            MAX_LOAD_KEYS,
            "LOAD_KEYS request",
            in ->
                new SealedKey(
                    in.vector(PUBLIC_KEY_SIZE),
                    in.vector(SEALED_NONCE_SIZE),
                    in.vector(SEALED_CIPHERTEXT_SIZE)));
    if (keys.isEmpty()) {
      throw malformed("LOAD_KEYS request", "no entries");
    }
    return keys;
  }

  public static byte[] encodeKeyLoadCounts(final KeyLoadCounts counts) {
    return Ssz.writeContainer()
        .uint32(counts.loaded())
        .uint32(counts.duplicates())
        .uint32(counts.rejected())
        .toBytes();
  }

  public static KeyLoadCounts decodeKeyLoadCounts(final byte[] body) throws IOException {
    return Ssz.readContainer(
        body, "LOAD_KEYS response", in -> new KeyLoadCounts(in.uint32(), in.uint32(), in.uint32()));
  }

  // ------------------------------------------------------------------ errors

  /**
   * {@code ErrorMessage}, a {@code List[Byte, 256]}, the body of every response other than {@code
   * OK}. Reduced to printable ASCII. Keep it free of anything that depends on secret data.
   */
  public static byte[] encodeErrorMessage(final String message) {
    return printableAscii(message, MAX_ERROR_MESSAGE_SIZE);
  }

  /** The error message of a refusal, as printable ASCII: it ends up in logs. */
  public static String decodeErrorMessage(final byte[] body) throws IOException {
    return printableAscii(Ssz.readByteList(body, MAX_ERROR_MESSAGE_SIZE, "error response"));
  }

  // ------------------------------------------------------------------ helpers

  /** SSZ has no empty container: a message that carries nothing has an empty body. */
  private static void requireEmpty(final byte[] body, final String what) throws IOException {
    if (body.length != 0) {
      throw malformed(what, "body not empty");
    }
  }

  /** The decoders' failure for a message rule, worded like the {@link Ssz} ones. */
  private static IOException malformed(final String what, final String reason) {
    return new IOException("Malformed " + what + ": " + reason);
  }

  /** Anything outside printable ASCII (line breaks, control characters, non-ASCII) becomes '?'. */
  private static String printableAscii(final byte[] bytes) {
    final StringBuilder result = new StringBuilder(bytes.length);
    for (final byte b : bytes) {
      final int c = b & 0xff;
      result.append(c >= 0x20 && c < 0x7f ? (char) c : '?');
    }
    return result.toString();
  }

  private static byte[] printableAscii(final String value, final int maxSize) {
    final String text = value.length() > maxSize ? value.substring(0, maxSize) : value;
    return printableAscii(text.getBytes(StandardCharsets.US_ASCII))
        .getBytes(StandardCharsets.US_ASCII);
  }
}
