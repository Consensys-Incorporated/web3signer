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

/** Produces the platform's evidence that binds a release key of the enclave. */
public interface EvidenceProvider {

  /** The evidence type reported by {@code GET_EVIDENCE}, one of {@code Protocol.EVIDENCE_*}. */
  int type();

  /**
   * Returns evidence that binds {@code releaseKeySpki} and {@code nonce}.
   *
   * @param releaseKeySpki X.509 SubjectPublicKeyInfo of an RSA key the enclave just generated
   * @param nonce caller nonce, at most 64 bytes, possibly empty
   * @throws EvidenceException when the platform cannot produce evidence
   */
  byte[] evidence(byte[] releaseKeySpki, byte[] nonce) throws EvidenceException;

  /** The platform could not produce evidence. The message reaches the host: no secrets in it. */
  final class EvidenceException extends Exception {
    private static final long serialVersionUID = 1L;

    public EvidenceException(final String message) {
      super(message);
    }
  }
}
