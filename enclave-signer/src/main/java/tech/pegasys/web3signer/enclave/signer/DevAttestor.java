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

/**
 * Development platform: the "attestation document" is the SPKI of the enclave RSA key itself. It
 * proves nothing and exists so that the same provisioning path runs in tests and local runs.
 */
public final class DevAttestor implements Attestor {
  @Override
  public byte[] attest(final byte[] publicKeySpki, final byte[] nonce) {
    return publicKeySpki.clone();
  }
}
