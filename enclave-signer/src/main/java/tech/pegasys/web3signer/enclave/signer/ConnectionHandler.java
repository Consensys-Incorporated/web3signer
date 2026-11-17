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

import static tech.pegasys.web3signer.enclave.protocol.Frames.OVERHEAD;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getUnsignedInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getUnsignedShort;
import static tech.pegasys.web3signer.enclave.protocol.Frames.putInt;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.BAD_REQUEST;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.INTERNAL_ERROR;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.LENGTH_PREFIX_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_FRAME_LENGTH;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_PUBLIC_KEYS_PAGE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.OK;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.PUBLIC_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.RESPONSE_FLAG;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SIGNATURE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.UNKNOWN_KEY;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.UNSUPPORTED;

import tech.pegasys.web3signer.enclave.protocol.Connection;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Payloads;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

/**
 * Serves one connection on its own thread. Handles every complete frame in its input buffer and
 * writes the responses together, once no complete request is left or the output buffer is full.
 *
 * <p>Provisioning state belongs to the connection: {@code Idle}, {@code KeyPending} (an RSA key
 * pair from {@code ATTEST} waits for its single unwrap) and {@code DekHeld} (the data key opens
 * {@code LOAD_KEYS} entries). It is discarded when the connection ends.
 */
final class ConnectionHandler {
  private static final int BUFFER_SIZE = 64 * 1024;
  private static final int SIGN_RESPONSE_SIZE = OVERHEAD + 1 + SIGNATURE_SIZE;

  private final Connection connection;
  private final SignerServer server;
  private final Blst.Scratch scratch;
  private final SecureRandom random = new SecureRandom();

  /** RSA key of the last ATTEST, used for at most one UNWRAP_DEK. Non-null in KeyPending. */
  private PrivateKey pendingKey;

  /** The data key. Non-null in DekHeld. */
  private byte[] dek;

  private byte[] in = new byte[BUFFER_SIZE];
  private int inStart;
  private int inEnd;
  private byte[] out = new byte[BUFFER_SIZE];
  private int outLength;

  ConnectionHandler(final Connection connection, final SignerServer server, final Arena arena) {
    this.connection = connection;
    this.server = server;
    this.scratch = new Blst.Scratch(arena);
  }

  /** Runs until the peer closes, an I/O error, or a frame with an impossible length. */
  void run() throws IOException {
    try {
      serve();
    } finally {
      discardProvisioningState();
    }
  }

  private void serve() throws IOException {
    while (true) {
      while (inEnd - inStart >= LENGTH_PREFIX_SIZE) {
        final long length = getUnsignedInt(in, inStart);
        if (!Frames.isValidLength(length)) {
          Log.warn("closing connection: frame length out of range");
          return;
        }
        final int total = LENGTH_PREFIX_SIZE + (int) length;
        if (inEnd - inStart < total) {
          makeRoom(total);
          break;
        }
        handle(inStart + LENGTH_PREFIX_SIZE, (int) length);
        inStart += total;
      }
      flush();
      if (inStart == inEnd) {
        inStart = 0;
        inEnd = 0;
      }
      if (inEnd == in.length) {
        makeRoom(in.length - inStart + 1);
      }
      final int n = connection.read(in, inEnd, in.length - inEnd);
      if (n < 0) {
        return;
      }
      inEnd += n;
    }
  }

  /** Makes sure a frame of {@code total} bytes starting at {@code inStart} fits the buffer. */
  private void makeRoom(final int total) {
    if (in.length - inStart >= total) {
      return;
    }
    final int pending = inEnd - inStart;
    final byte[] target =
        total > in.length
            ? new byte
                [Math.min(Math.max(total, in.length * 2), LENGTH_PREFIX_SIZE + MAX_FRAME_LENGTH)]
            : in;
    System.arraycopy(in, inStart, target, 0, pending);
    in = target;
    inStart = 0;
    inEnd = pending;
  }

  private void flush() throws IOException {
    if (outLength > 0) {
      connection.write(out, 0, outLength);
      outLength = 0;
    }
  }

  /** Reserves {@code size} bytes in the output buffer, writing what it holds first if needed. */
  private int reserve(final int size) throws IOException {
    if (outLength + size > out.length) {
      flush();
      if (size > out.length) {
        out = new byte[size];
      }
    }
    final int at = outLength;
    outLength += size;
    return at;
  }

  /** Handles the frame whose type byte is at {@code at} and whose length is {@code length}. */
  private void handle(final int at, final int length) throws IOException {
    final int type = in[at] & 0xff;
    final int requestId = getInt(in, at + 1);
    final int payload = at + Protocol.FRAME_HEADER_SIZE;
    final int payloadLength = length - Protocol.FRAME_HEADER_SIZE;
    try {
      switch (type) {
        case Protocol.SIGN -> sign(requestId, payload, payloadLength);
        case Protocol.STATUS -> status(requestId, payloadLength);
        case Protocol.GET_PUBLIC_KEYS -> publicKeys(requestId, payload, payloadLength);
        case Protocol.ATTEST -> attest(requestId, payload, payloadLength);
        case Protocol.UNWRAP_DEK -> unwrapDek(requestId, payload, payloadLength);
        case Protocol.LOAD_KEYS -> loadKeys(requestId, payload, payloadLength);
        default -> respond(type, requestId, Payloads.errorResponse(UNSUPPORTED));
      }
    } catch (final RuntimeException e) {
      Log.error("request failed", e);
      respond(type, requestId, Payloads.errorResponse(INTERNAL_ERROR));
    }
  }

  private void respond(final int type, final int requestId, final byte[] payload)
      throws IOException {
    final int at = reserve(OVERHEAD + payload.length);
    Frames.putHeader(out, at, type | RESPONSE_FLAG, requestId, payload.length);
    System.arraycopy(payload, 0, out, at + OVERHEAD, payload.length);
  }

  private void sign(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (payloadLength < PUBLIC_KEY_SIZE + 2
        || payloadLength != PUBLIC_KEY_SIZE + 2 + getUnsignedShort(in, payload + PUBLIC_KEY_SIZE)) {
      respond(Protocol.SIGN, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    final MemorySegment secret = server.keys().lookup(in, payload);
    if (secret == null) {
      respond(Protocol.SIGN, requestId, Payloads.errorResponse(UNKNOWN_KEY));
      return;
    }
    final int at = reserve(SIGN_RESPONSE_SIZE);
    Frames.putHeader(out, at, Protocol.SIGN | RESPONSE_FLAG, requestId, 1 + SIGNATURE_SIZE);
    out[at + OVERHEAD] = OK;
    server
        .blst()
        .sign(
            scratch,
            secret,
            in,
            payload + PUBLIC_KEY_SIZE + 2,
            payloadLength - PUBLIC_KEY_SIZE - 2,
            out,
            at + OVERHEAD + 1);
  }

  private void status(final int requestId, final int payloadLength) throws IOException {
    if (payloadLength != 0) {
      respond(Protocol.STATUS, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    respond(
        Protocol.STATUS,
        requestId,
        Payloads.statusResponse(
            server.platform(),
            Runtime.getRuntime().availableProcessors(),
            server.keys().size(),
            server.bootId(),
            server.version()));
  }

  private void publicKeys(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (payloadLength != 8
        || getInt(in, payload + 4) < 1
        || getInt(in, payload + 4) > MAX_PUBLIC_KEYS_PAGE) {
      respond(Protocol.GET_PUBLIC_KEYS, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    final KeyTable.Page page =
        server.keys().page(getUnsignedInt(in, payload), getInt(in, payload + 4));
    final byte[] response = new byte[9 + page.publicKeys().length];
    response[0] = OK;
    putInt(response, 1, page.total());
    putInt(response, 5, page.count());
    System.arraycopy(page.publicKeys(), 0, response, 9, page.publicKeys().length);
    respond(Protocol.GET_PUBLIC_KEYS, requestId, response);
  }

  /** Back to Idle: drops the pending RSA key and zeroes the data key. */
  private void discardProvisioningState() {
    pendingKey = null;
    if (dek != null) {
      Arrays.fill(dek, (byte) 0);
      dek = null;
    }
  }

  private void attest(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (payloadLength < 1
        || (in[payload] & 0xff) > Protocol.MAX_NONCE_SIZE
        || payloadLength != 1 + (in[payload] & 0xff)) {
      respond(Protocol.ATTEST, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    discardProvisioningState();
    final byte[] nonce = Arrays.copyOfRange(in, payload + 1, payload + payloadLength);
    final KeyPair keyPair;
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      // never SecureRandom.getInstanceStrong(): /dev/random can block inside the enclave
      generator.initialize(2048, random);
      keyPair = generator.generateKeyPair();
    } catch (final NoSuchAlgorithmException e) {
      Log.error("RSA key generation failed", e);
      respond(Protocol.ATTEST, requestId, Payloads.errorResponse(INTERNAL_ERROR));
      return;
    }
    final byte[] document;
    try {
      document = server.attestor().attest(keyPair.getPublic().getEncoded(), nonce);
    } catch (final Attestor.AttestationException e) {
      Log.warn("attestation failed: " + e.getMessage());
      respond(Protocol.ATTEST, requestId, Payloads.errorResponse(Protocol.ATTESTATION_FAILED));
      return;
    }
    pendingKey = keyPair.getPrivate();
    Log.info("attestation document issued (" + document.length + " bytes)");
    respond(Protocol.ATTEST, requestId, Payloads.attestResponse(document));
  }

  private void unwrapDek(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (pendingKey == null) {
      respond(Protocol.UNWRAP_DEK, requestId, Payloads.errorResponse(Protocol.INVALID_STATE));
      return;
    }
    // the key pair serves exactly one attempt, whatever its outcome
    final PrivateKey key = pendingKey;
    discardProvisioningState();
    if (payloadLength < 5 || getUnsignedInt(in, payload + 1) != payloadLength - 5) {
      respond(Protocol.UNWRAP_DEK, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    if ((in[payload] & 0xff) != Protocol.BLOB_FORMAT_CMS) {
      respond(Protocol.UNWRAP_DEK, requestId, Payloads.errorResponse(UNSUPPORTED));
      return;
    }
    try {
      dek = DekUnwrapper.unwrap(key, Arrays.copyOfRange(in, payload + 5, payload + payloadLength));
    } catch (final DekUnwrapper.UnwrapException e) {
      Log.warn("data key unwrap failed");
      respond(Protocol.UNWRAP_DEK, requestId, Payloads.errorResponse(Protocol.UNWRAP_FAILED));
      return;
    }
    Log.info("data key unwrapped");
    respond(Protocol.UNWRAP_DEK, requestId, Payloads.unwrapDekResponse());
  }

  private void loadKeys(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (dek == null) {
      respond(Protocol.LOAD_KEYS, requestId, Payloads.errorResponse(Protocol.INVALID_STATE));
      return;
    }
    final long announced = payloadLength < 4 ? -1 : getUnsignedInt(in, payload);
    if (announced < 1
        || announced > Protocol.MAX_LOAD_KEYS
        || payloadLength != 4 + announced * Protocol.SEALED_KEY_SIZE) {
      respond(Protocol.LOAD_KEYS, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    final int count = (int) announced; // 1..MAX_LOAD_KEYS
    final KeyTable keys = server.keys();
    final SealedKeyOpener opener = new SealedKeyOpener(server.blst(), scratch, dek);
    final Set<String> seen = new HashSet<>();
    final byte[] accepted = new byte[count * PUBLIC_KEY_SIZE];
    int acceptedCount = 0;
    int duplicates = 0;
    int rejected = 0;
    try (Arena staging = Arena.ofConfined()) {
      final MemorySegment scalars = staging.allocate((long) count * Blst.SCALAR_SIZE, 8);
      try {
        for (int i = 0; i < count; i++) {
          final int entry = payload + 4 + i * Protocol.SEALED_KEY_SIZE;
          final byte[] publicKey = Arrays.copyOfRange(in, entry, entry + PUBLIC_KEY_SIZE);
          if (keys.contains(publicKey) || !seen.add(HexFormat.of().formatHex(publicKey))) {
            duplicates++;
            continue;
          }
          final MemorySegment scalar =
              scalars.asSlice((long) acceptedCount * Blst.SCALAR_SIZE, Blst.SCALAR_SIZE);
          if (opener.open(in, entry, scalar)) {
            System.arraycopy(
                publicKey, 0, accepted, acceptedCount * PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
            acceptedCount++;
          } else {
            rejected++;
          }
        }
        final int added = acceptedCount == 0 ? 0 : keys.addAll(accepted, scalars, acceptedCount);
        // another connection may have added some of these keys meanwhile
        duplicates += acceptedCount - added;
        Log.info(
            "load keys: "
                + added
                + " loaded, "
                + duplicates
                + " duplicates, "
                + rejected
                + " rejected, "
                + keys.size()
                + " in total");
        respond(
            Protocol.LOAD_KEYS,
            requestId,
            Payloads.loadKeysResponse(new LoadResult(added, duplicates, rejected)));
      } finally {
        scalars.fill((byte) 0);
      }
    }
  }
}
