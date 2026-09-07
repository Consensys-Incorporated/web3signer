/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres;

import org.apache.tuweni.bytes.Bytes;

/**
 * A decrypted BLS private key read from the postgres keystore. Deliberately free of any BLS/Teku
 * type so this module has no dependency on the {@code signing} module - the {@code signing}
 * module's {@code BlsPostgresBulkLoader} maps this to a {@code BlsArtifactSigner}.
 */
public record DecryptedBlsKey(String keyIdentifier, Bytes rawSecretKeyBytes) {}
