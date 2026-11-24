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

import tech.pegasys.web3signer.enclave.protocol.Protocol;

/**
 * Development platform: the "evidence" is the SPKI of the release key itself. It proves nothing and
 * exists so that the same provisioning path runs in tests and local runs.
 */
public final class DevEvidenceProvider implements EvidenceProvider {
  @Override
  public int type() {
    return Protocol.EVIDENCE_DEV;
  }

  @Override
  public byte[] evidence(final byte[] releaseKeySpki, final byte[] nonce) {
    return releaseKeySpki.clone();
  }
}
