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
package tech.pegasys.web3signer.enclave.client;

import tech.pegasys.web3signer.enclave.client.EnclaveClient.BodyDecoder;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.KeyLoadCounts;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Messages.Status;
import tech.pegasys.web3signer.enclave.protocol.Messages.UnwrapDekRequest;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.protocol.UnsupportedProtocolVersionException;
import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;

/**
 * Loads sealed BLS keys into the enclave signer. The enclave gives evidence for a fresh release
 * key, a key broker releases the data key to that release key, the enclave unwraps it, and then
 * opens the sealed keys with it.
 *
 * <p>Every step runs on one connection: the enclave keeps the release key and the data key only for
 * that connection, so nothing is retried. An I/O error, a malformed answer or a signer of another
 * protocol version closes the session. Not thread safe.
 */
public final class ProvisioningSession implements Closeable {
  private final EnclaveClient client;
  private final Connection connection;

  ProvisioningSession(final EnclaveClient client, final Connection connection) {
    this.client = client;
    this.connection = connection;
  }

  /**
   * The signer's status: platform, key count, boot id and version.
   *
   * @throws UnsupportedProtocolVersionException when the signer speaks another protocol version;
   *     retrying cannot help
   */
  public Status status() {
    return send(Protocol.STATUS, Messages.encodeStatusRequest(), Messages::decodeStatus);
  }

  /**
   * Asks the enclave for evidence bound to a fresh release key of its own.
   *
   * @param nonce at most {@value Protocol#MAX_NONCE_SIZE} bytes, bound into the evidence
   */
  public Evidence evidence(final byte[] nonce) {
    return send(Protocol.GET_EVIDENCE, Messages.encodeNonce(nonce), Messages::decodeEvidence);
  }

  /** Hands the release blob for the release key of the last {@code GET_EVIDENCE} to the enclave. */
  public void unwrapDek(final int format, final byte[] blob) {
    send(
        Protocol.UNWRAP_DEK,
        Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(format, blob)),
        body -> {
          Messages.decodeUnwrapDekResponse(body);
          return null;
        });
  }

  /**
   * Loads sealed keys in requests of at most {@value Protocol#MAX_LOAD_KEYS} and adds up the
   * counts.
   *
   * @throws PartialLoadException when a request fails after earlier ones loaded keys; those keys
   *     stay in the enclave, and the exception carries their counts
   */
  public KeyLoadCounts loadKeys(final List<SealedKey> keys) {
    KeyLoadCounts total = KeyLoadCounts.EMPTY;
    for (int from = 0; from < keys.size(); from += Protocol.MAX_LOAD_KEYS) {
      final List<SealedKey> chunk =
          keys.subList(from, Math.min(keys.size(), from + Protocol.MAX_LOAD_KEYS));
      try {
        total =
            total.plus(
                send(
                    Protocol.LOAD_KEYS,
                    Messages.encodeSealedKeys(chunk),
                    Messages::decodeKeyLoadCounts));
      } catch (final EnclaveException | EnclaveUnavailableException e) {
        if (from == 0) {
          throw e;
        }
        throw new PartialLoadException(total, e);
      }
    }
    return total;
  }

  private <T> T send(final int opcode, final byte[] body, final BodyDecoder<T> decoder) {
    try {
      return decoder.decode(client.sendAndReceive(connection, opcode, body));
    } catch (final EnclaveException refused) {
      throw refused; // a refusal leaves the session usable
    } catch (final IOException e) {
      client.closeConnection(connection);
      throw new EnclaveUnavailableException("Provisioning connection failed", e);
    } catch (final Throwable e) {
      // anything else, a version mismatch or an Error included, leaves the session unusable
      client.closeConnection(connection);
      throw e;
    }
  }

  @Override
  public void close() {
    client.closeConnection(connection);
  }
}
