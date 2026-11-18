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
package tech.pegasys.web3signer.signing;

import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.web3signer.enclave.protocol.EnclaveClient;
import tech.pegasys.web3signer.enclave.protocol.EnclaveException;
import tech.pegasys.web3signer.enclave.protocol.EnclaveUnavailableException;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.signing.util.IdentifierUtils;

import java.util.HexFormat;

import org.apache.tuweni.bytes.Bytes;

/**
 * A BLS signer whose secret key lives in an enclave signer. Read-only: the key cannot be deleted or
 * replaced through Web3Signer.
 */
public class EnclaveBlsArtifactSigner implements ArtifactSigner {
  private final EnclaveClient client;
  private final byte[] publicKey;
  private final String identifier;

  public EnclaveBlsArtifactSigner(final EnclaveClient client, final byte[] publicKey) {
    this.client = client;
    this.publicKey = publicKey.clone();
    this.identifier = IdentifierUtils.normaliseIdentifier(HexFormat.of().formatHex(publicKey));
  }

  @Override
  public String getIdentifier() {
    return identifier;
  }

  /**
   * @throws SignerUnavailableException when the enclave signer cannot be reached, times out, or
   *     does not hold the key (an enclave signer restarted but not provisioned yet)
   */
  @Override
  public BlsArtifactSignature sign(final Bytes message) {
    final byte[] signature;
    try {
      signature = client.sign(publicKey, message.toArrayUnsafe());
    } catch (final EnclaveUnavailableException e) {
      throw unavailable(e);
    } catch (final EnclaveException e) {
      if (e.status() == Protocol.UNKNOWN_KEY) {
        throw unavailable(e);
      }
      throw e;
    }
    // lazy: no point decompression
    return new BlsArtifactSignature(BLSSignature.fromBytesCompressed(Bytes.wrap(signature)));
  }

  /** Wraps an enclave failure; the message carries the failure's and its root cause's messages. */
  public static SignerUnavailableException unavailable(final RuntimeException e) {
    String rootCauseMessage = null;
    for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
      if (cause.getMessage() != null) {
        rootCauseMessage = cause.getMessage();
      }
    }
    final String message =
        rootCauseMessage == null ? e.getMessage() : e.getMessage() + ": " + rootCauseMessage;
    return new SignerUnavailableException("Signer unavailable: " + message, e);
  }

  @Override
  public KeyType getKeyType() {
    return KeyType.BLS;
  }

  @Override
  public boolean equals(final Object o) {
    return o instanceof EnclaveBlsArtifactSigner other && identifier.equals(other.identifier);
  }

  @Override
  public int hashCode() {
    return identifier.hashCode();
  }

  @Override
  public String toString() {
    return "EnclaveBlsArtifactSigner{" + identifier + ", " + client.target() + "}";
  }
}
