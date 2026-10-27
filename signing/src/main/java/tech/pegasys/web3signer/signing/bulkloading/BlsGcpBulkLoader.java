/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.keystorage.gcp.GcpSecretManager;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.config.GcpSecretManagerParameters;
import tech.pegasys.web3signer.signing.config.metadata.SignerOrigin;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class BlsGcpBulkLoader {
  private static final Logger LOG = LogManager.getLogger();

  public MappedResults<ArtifactSigner> load(final GcpSecretManagerParameters parameters) {
    try (final GcpSecretManager gcpSecretManager = new GcpSecretManager()) {
      return gcpSecretManager.mapSecrets(
          parameters.getProjectId(),
          parameters.getFilter(),
          (key, value) -> {
            final Bytes privateKeyBytes = Bytes.fromHexString(value);
            final BLSKeyPair keyPair =
                new BLSKeyPair(BLSSecretKey.fromBytes(Bytes32.wrap(privateKeyBytes)));
            return new BlsArtifactSigner(keyPair, SignerOrigin.GCP);
          });
    } catch (IOException e) {
      LOG.error("Error reading GCP secrets", e);
      return MappedResults.errorResult();
    }
  }
}
