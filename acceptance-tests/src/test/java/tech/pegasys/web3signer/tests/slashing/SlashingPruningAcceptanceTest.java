/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.tests.slashing;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.web3signer.dsl.utils.Eth2RequestUtils.createAttestationRequest;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.web3signer.BLSTestUtil;
import tech.pegasys.web3signer.dsl.signer.Signer;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.utils.Eth2RequestUtils;
import tech.pegasys.web3signer.dsl.utils.MetadataFileHelpers;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import db.DatabaseUtil;
import db.DatabaseUtil.TestDatabaseInfo;
import org.apache.tuweni.bytes.Bytes32;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class SlashingPruningAcceptanceTest extends AcceptanceTestBase {

  private static final MetadataFileHelpers METADATA_FILE_HELPERS = new MetadataFileHelpers();
  public static final String DB_USERNAME = "postgres";
  public static final String DB_PASSWORD = "postgres";

  protected final BLSKeyPair keyPair = BLSTestUtil.randomKeyPair(0);

  @Test
  void slashingDataIsPruned(
      @TempDir final Path dataSignerDirectory, @TempDir final Path prunerSignerDirectory)
      throws IOException {
    final TestDatabaseInfo testDatabaseInfo = DatabaseUtil.create();
    final String dbUrl = testDatabaseInfo.databaseUrl();
    final Jdbi jdbi = testDatabaseInfo.jdbi();

    final Path dataSignerKeyConfigFile = dataSignerDirectory.resolve("keyfile.yaml");
    METADATA_FILE_HELPERS.createUnencryptedYamlFileAt(
        dataSignerKeyConfigFile, keyPair.getSecretKey().toBytes().toHexString(), KeyType.BLS);

    final SignerConfigurationBuilder signerBuilder =
        new SignerConfigurationBuilder()
            .withMode("eth2")
            .withSlashingEnabled(true)
            .withSlashingProtectionDbUsername(DB_USERNAME)
            .withSlashingProtectionDbPassword(DB_PASSWORD)
            .withSlashingProtectionDbUrl(dbUrl)
            .withNetwork("minimal")
            .withKeyStoreDirectory(dataSignerDirectory);

    final Signer dataCreatingSigner = new Signer(signerBuilder.build(), null);
    dataCreatingSigner.start();
    dataCreatingSigner.awaitStartupCompletion();

    // populate slashing database with 2 block signings and 2 attestation signings
    dataCreatingSigner.eth2Sign(
        keyPair.getPublicKey().toString(), createAttestationRequest(1, 2, UInt64.ZERO));
    dataCreatingSigner.eth2Sign(
        keyPair.getPublicKey().toString(), createAttestationRequest(2, 3, UInt64.ZERO));
    dataCreatingSigner.eth2Sign(
        keyPair.getPublicKey().toString(),
        Eth2RequestUtils.createBlockRequest(UInt64.valueOf(1), Bytes32.fromHexString("0x1111")));
    dataCreatingSigner.eth2Sign(
        keyPair.getPublicKey().toString(),
        Eth2RequestUtils.createBlockRequest(UInt64.valueOf(2), Bytes32.fromHexString("0x1111")));
    dataCreatingSigner.shutdown();

    final List<Map<String, Object>> attestationsBeforePruning = getAttestations(jdbi);
    final List<Map<String, Object>> blocksBeforePruning = getSignedBlocks(jdbi);
    assertThat(attestationsBeforePruning).hasSize(2);
    assertThat(blocksBeforePruning).hasSize(2);

    // start signer with pruning enabled at boot configured to only keep one block and attestation
    final Path prunerKeyConfigFile = prunerSignerDirectory.resolve("keyfile.yaml");
    METADATA_FILE_HELPERS.createUnencryptedYamlFileAt(
        prunerKeyConfigFile, keyPair.getSecretKey().toBytes().toHexString(), KeyType.BLS);

    signerBuilder
        .withSlashingPruningEnabled(true)
        .withSlashingPruningEnabledAtBoot(true)
        .withSlashingPruningEpochsToKeep(1)
        .withSlashingPruningSlotsPerEpoch(1)
        .withSlashingPruningInterval(1)
        .withKeyStoreDirectory(prunerSignerDirectory);
    final Signer pruningSigner = new Signer(signerBuilder.build(), null);
    try {
      pruningSigner.start();
      pruningSigner.awaitStartupCompletion();

      final List<Map<String, Object>> attestations = getAttestations(jdbi);
      final Map<String, Object> expectedHeadAttestation = attestationsBeforePruning.get(1);
      assertThat(attestations).hasSize(1);
      assertThat(attestations.get(0).get("validator_id"))
          .isEqualTo(expectedHeadAttestation.get("validator_id"));
      assertThat(attestations.get(0).get("source_epoch"))
          .isEqualTo(expectedHeadAttestation.get("source_epoch"));
      assertThat(attestations.get(0).get("target_epoch"))
          .isEqualTo(expectedHeadAttestation.get("target_epoch"));
      assertThat(attestations.get(0).get("signing_root"))
          .isEqualTo(expectedHeadAttestation.get("signing_root"));

      final List<Map<String, Object>> blocks = getSignedBlocks(jdbi);
      final Map<String, Object> expectedHeadBlock = blocksBeforePruning.get(1);
      assertThat(blocks).hasSize(1);
      assertThat(blocks.get(0).get("validator_id"))
          .isEqualTo(expectedHeadBlock.get("validator_id"));
      assertThat(blocks.get(0).get("slot")).isEqualTo(expectedHeadBlock.get("slot"));
      assertThat(blocks.get(0).get("signing_root"))
          .isEqualTo(expectedHeadBlock.get("signing_root"));
    } finally {
      pruningSigner.shutdown();
    }
  }

  private List<Map<String, Object>> getSignedBlocks(final Jdbi jdbi) {
    return jdbi.withHandle(h -> h.select("SELECT * from signed_blocks").mapToMap().list());
  }

  private List<Map<String, Object>> getAttestations(final Jdbi jdbi) {
    return jdbi.withHandle(h -> h.select("SELECT * from signed_attestations").mapToMap().list());
  }
}
