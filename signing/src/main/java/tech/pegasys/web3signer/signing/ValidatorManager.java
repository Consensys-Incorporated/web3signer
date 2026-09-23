/*
 * Copyright 2022 ConsenSys AG.
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

import org.apache.tuweni.bytes.Bytes;

public interface ValidatorManager {

  /// Delete validator for provided public key
  ///
  /// @param publicKey An instance of Bytes representing public key
  void deleteValidator(final Bytes publicKey);

  /// Add validator from a decrypted signer
  ///
  /// @param signer instance of BlsArtifactSigner
  /// @param keystoreFileRecord keystore file record associated with manager. May be `null` for
  ///   managers that manages validators only in-memory
  void addValidator(final BlsArtifactSigner signer, final KeystoreFileRecord keystoreFileRecord);
}
