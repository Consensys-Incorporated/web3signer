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

/** Produces an attestation document that binds a public key of the enclave. */
public interface Attestor {

  /**
   * Returns an attestation document whose public key field is {@code publicKeySpki}.
   *
   * @param publicKeySpki X.509 SubjectPublicKeyInfo of an RSA key the enclave just generated
   * @param nonce caller nonce, at most 64 bytes, possibly empty
   * @return the attestation document
   * @throws AttestationException when the platform cannot produce one
   */
  byte[] attest(byte[] publicKeySpki, byte[] nonce) throws AttestationException;

  /** The platform could not produce an attestation document. */
  final class AttestationException extends Exception {
    private static final long serialVersionUID = 1L;

    public AttestationException(final String message) {
      super(message);
    }

    public AttestationException(final String message, final Throwable cause) {
      super(message, cause);
    }
  }
}
