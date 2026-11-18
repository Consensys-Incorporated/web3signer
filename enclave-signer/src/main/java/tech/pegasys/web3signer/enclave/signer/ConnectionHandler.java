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

import static tech.pegasys.web3signer.enclave.protocol.Protocol.BAD_REQUEST;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.INTERNAL_ERROR;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.OK;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.PUBLIC_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SIGNATURE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.UNKNOWN_KEY;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.UNSUPPORTED;

import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Messages.PageRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Messages.SignRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.UnwrapDekRequest;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.EOFException;
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
import java.util.List;
import java.util.Set;

/**
 * Serves one connection on its own thread: reads a request, answers it, and reads the next.
 *
 * <p>Provisioning state belongs to the connection: {@code Idle}, {@code KeyPending} (a release key
 * from {@code GET_EVIDENCE} waits for its single unwrap) and {@code DekHeld} (the data key opens
 * {@code LOAD_KEYS} entries). It is discarded when the connection ends.
 *
 * <p>Error messages go to the host. They are fixed text or come from the codec, never from anything
 * that depends on secret data, and every unwrap failure gets the same one.
 */
final class ConnectionHandler {
  private static final byte[] UNKNOWN_KEY_MESSAGE =
      Messages.encodeErrorMessage("the enclave does not hold this key");
  private static final byte[] UNWRAP_FAILED_MESSAGE =
      Messages.encodeErrorMessage("the release blob did not open");

  private final Connection connection;
  private final SignerServer server;
  private final Blst.Scratch scratch;
  private final SecureRandom random = new SecureRandom();

  /** Release key of the last GET_EVIDENCE, used for at most one UNWRAP_DEK. Set in KeyPending. */
  private PrivateKey pendingKey;

  /** The data key. Non-null in DekHeld. */
  private byte[] dek;

  ConnectionHandler(final Connection connection, final SignerServer server, final Arena arena) {
    this.connection = connection;
    this.server = server;
    this.scratch = new Blst.Scratch(arena);
  }

  /**
   * Runs until the peer closes. An I/O error or a frame with an impossible length ends it with an
   * exception.
   */
  void run() throws IOException {
    try {
      while (true) {
        final Frame request;
        try {
          request = Frames.read(connection);
        } catch (final EOFException peerClosed) {
          return;
        }
        handle(request.requestId(), request.kind(), request.body());
      }
    } finally {
      discardProvisioningState();
    }
  }

  private void handle(final int requestId, final int opcode, final byte[] body) throws IOException {
    try {
      switch (opcode) {
        case Protocol.SIGN -> sign(requestId, body);
        case Protocol.STATUS -> status(requestId, body);
        case Protocol.GET_PUBLIC_KEYS -> publicKeys(requestId, body);
        case Protocol.GET_EVIDENCE -> evidence(requestId, body);
        case Protocol.UNWRAP_DEK -> unwrapDek(requestId, body);
        case Protocol.LOAD_KEYS -> loadKeys(requestId, body);
        default ->
            refuse(requestId, UNSUPPORTED, "unknown opcode 0x" + Integer.toHexString(opcode));
      }
    } catch (final RuntimeException e) {
      Log.error("request failed", e);
      refuse(requestId, INTERNAL_ERROR, "internal error");
    }
  }

  private void respond(final int requestId, final byte[] body) throws IOException {
    respond(requestId, OK, body);
  }

  private void respond(final int requestId, final int result, final byte[] body)
      throws IOException {
    Frames.write(connection, new Frame(requestId, result, body));
  }

  private void refuse(final int requestId, final int result, final String message)
      throws IOException {
    respond(requestId, result, Messages.encodeErrorMessage(message));
  }

  private void sign(final int requestId, final byte[] body) throws IOException {
    final SignRequest request;
    try {
      request = Messages.decodeSignRequest(body);
    } catch (final IOException malformed) {
      refuse(requestId, BAD_REQUEST, malformed.getMessage());
      return;
    }
    final MemorySegment secret = server.keys().lookup(request.publicKey(), 0);
    if (secret == null) {
      respond(requestId, UNKNOWN_KEY, UNKNOWN_KEY_MESSAGE);
      return;
    }
    final byte[] signature = new byte[SIGNATURE_SIZE];
    server.blst().sign(scratch, secret, request.signingRoot(), 0, signature, 0);
    respond(requestId, Messages.encodeSignature(signature));
  }

  private void status(final int requestId, final byte[] body) throws IOException {
    try {
      Messages.decodeStatusRequest(body);
    } catch (final IOException malformed) {
      refuse(requestId, BAD_REQUEST, malformed.getMessage());
      return;
    }
    respond(
        requestId,
        Messages.encodeStatus(
            server.platform(),
            Runtime.getRuntime().availableProcessors(),
            server.keys().size(),
            server.bootId(),
            server.version()));
  }

  private void publicKeys(final int requestId, final byte[] body) throws IOException {
    final PageRequest request;
    try {
      request = Messages.decodePageRequest(body);
    } catch (final IOException malformed) {
      refuse(requestId, BAD_REQUEST, malformed.getMessage());
      return;
    }
    respond(
        requestId,
        Messages.encodePublicKeys(server.keys().page(request.offset(), request.limit())));
  }

  /** Back to Idle: drops the pending release key and zeroes the data key. */
  private void discardProvisioningState() {
    pendingKey = null;
    if (dek != null) {
      Arrays.fill(dek, (byte) 0);
      dek = null;
    }
  }

  private void evidence(final int requestId, final byte[] body) throws IOException {
    final byte[] nonce;
    try {
      nonce = Messages.decodeEvidenceRequest(body);
    } catch (final IOException malformed) {
      refuse(requestId, BAD_REQUEST, malformed.getMessage());
      return;
    }
    discardProvisioningState();
    final KeyPair keyPair;
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      // never SecureRandom.getInstanceStrong(): /dev/random can block inside the enclave
      generator.initialize(2048, random);
      keyPair = generator.generateKeyPair();
    } catch (final NoSuchAlgorithmException e) {
      Log.error("RSA key generation failed", e);
      refuse(requestId, INTERNAL_ERROR, "release key generation failed");
      return;
    }
    final EvidenceProvider provider = server.evidenceProvider();
    final byte[] releaseKey = keyPair.getPublic().getEncoded();
    final byte[] evidence;
    try {
      evidence = provider.evidence(releaseKey, nonce);
    } catch (final EvidenceProvider.EvidenceException e) {
      Log.warn("evidence failed: " + e.getMessage());
      refuse(requestId, Protocol.EVIDENCE_FAILED, e.getMessage());
      return;
    }
    pendingKey = keyPair.getPrivate();
    Log.info("evidence issued (" + evidence.length + " bytes)");
    respond(
        requestId, Messages.encodeEvidence(new Evidence(provider.type(), releaseKey, evidence)));
  }

  private void unwrapDek(final int requestId, final byte[] body) throws IOException {
    if (pendingKey == null) {
      refuse(requestId, Protocol.INVALID_STATE, "no release key: GET_EVIDENCE first");
      return;
    }
    // the release key serves exactly one attempt, whatever its outcome
    final PrivateKey key = pendingKey;
    discardProvisioningState();
    final UnwrapDekRequest request;
    try {
      request = Messages.decodeUnwrapDekRequest(body);
    } catch (final IOException malformed) {
      refuse(requestId, BAD_REQUEST, malformed.getMessage());
      return;
    }
    if (request.format() != Protocol.BLOB_FORMAT_CMS) {
      refuse(requestId, UNSUPPORTED, "unsupported blob format " + request.format());
      return;
    }
    try {
      dek = DekUnwrapper.unwrap(key, request.blob());
    } catch (final DekUnwrapper.UnwrapException e) {
      Log.warn("data key unwrap failed");
      respond(requestId, Protocol.UNWRAP_FAILED, UNWRAP_FAILED_MESSAGE);
      return;
    }
    Log.info("data key unwrapped");
    respond(requestId, Messages.encodeUnwrapDekResponse());
  }

  private void loadKeys(final int requestId, final byte[] body) throws IOException {
    if (dek == null) {
      refuse(requestId, Protocol.INVALID_STATE, "no data key: UNWRAP_DEK first");
      return;
    }
    final List<SealedKey> entries;
    try {
      entries = Messages.decodeLoadKeysRequest(body);
    } catch (final IOException malformed) {
      refuse(requestId, BAD_REQUEST, malformed.getMessage());
      return;
    }
    final int count = entries.size(); // 1..MAX_LOAD_KEYS
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
        for (final SealedKey entry : entries) {
          final byte[] publicKey = entry.publicKey();
          final String publicKeyHex = HexFormat.of().formatHex(publicKey);
          if (keys.contains(publicKey) || seen.contains(publicKeyHex)) {
            duplicates++;
            continue;
          }
          final MemorySegment scalar =
              scalars.asSlice((long) acceptedCount * Blst.SCALAR_SIZE, Blst.SCALAR_SIZE);
          if (opener.open(entry, scalar)) {
            // only an accepted entry claims its key: a rejected one must not block a valid one
            seen.add(publicKeyHex);
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
        respond(requestId, Messages.encodeLoadResult(new LoadResult(added, duplicates, rejected)));
      } finally {
        scalars.fill((byte) 0);
      }
    }
  }
}
