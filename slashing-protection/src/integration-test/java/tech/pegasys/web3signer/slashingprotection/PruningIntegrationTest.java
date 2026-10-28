/*
 * Copyright 2021 ConsenSys AG.
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
package tech.pegasys.web3signer.slashingprotection;

import static db.DatabaseUtil.PASSWORD;
import static db.DatabaseUtil.USERNAME;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.slashingprotection.dao.HighWatermark;
import tech.pegasys.web3signer.slashingprotection.dao.MetadataDao;
import tech.pegasys.web3signer.slashingprotection.dao.SignedAttestation;
import tech.pegasys.web3signer.slashingprotection.dao.SignedBlock;
import tech.pegasys.web3signer.slashingprotection.dao.SigningWatermark;

import java.util.List;

import dsl.TestSlashingProtectionParameters;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class PruningIntegrationTest extends IntegrationTestBase {

  @ParameterizedTest
  @CsvSource({
    "1, 1, 9, 9",
    "5, 1, 5, 5",
    "9, 1, 1, 1, 1",
    "10, 1, 0, 0",
    "20, 1, 0, 0",
    "1, 2, 9, 8",
    "3, 2, 7, 4"
  })
  void prunesDataForRegisteredValidator(
      final int amountToKeep,
      final int slotsPerEpoch,
      final int expectedLowestPopulatedEpoch,
      final int expectedLowestPopulatedSlot) {
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(
                databaseUrl, USERNAME, PASSWORD, amountToKeep, slotsPerEpoch));
    final int size = 10;
    insertValidatorAndCreateSlashingData(
        slashingProtectionContext.getRegisteredValidators(), size, size, 1);
    final List<SignedAttestation> allAttestations = fetchAttestations(1);
    final List<SignedBlock> allBlocks = fetchBlocks(1);

    slashingProtectionContext.getPruner().prune();

    final List<SignedAttestation> expectedAttestations =
        allAttestations.subList(expectedLowestPopulatedEpoch, size);
    final List<SignedAttestation> attestationsInDatabase = fetchAttestations(1);
    assertThat(attestationsInDatabase)
        .usingRecursiveFieldByFieldElementComparator()
        .isEqualTo(expectedAttestations);

    final List<SignedBlock> expectedBlocks = allBlocks.subList(expectedLowestPopulatedSlot, size);
    final List<SignedBlock> blocks = fetchBlocks(1);
    assertThat(blocks).usingRecursiveFieldByFieldElementComparator().isEqualTo(expectedBlocks);

    assertThat(getWatermark(1))
        .usingRecursiveComparison()
        .isEqualTo(
            new SigningWatermark(
                1,
                UInt64.valueOf(expectedLowestPopulatedSlot),
                UInt64.valueOf(expectedLowestPopulatedEpoch),
                UInt64.valueOf(expectedLowestPopulatedEpoch)));
  }

  @Test
  void dataUnchangedForNonRegisteredValidators() {
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 1, 1));
    jdbi.withHandle(h -> validators.registerValidators(h, List.of(Bytes.of(1))));
    createSlashingData(2, 2, 1);
    insertValidatorAndCreateSlashingData(
        slashingProtectionContext.getRegisteredValidators(), 2, 2, 2);

    slashingProtectionContext.getPruner().prune();

    final List<SignedAttestation> attestationsForValidator1 = fetchAttestations(1);
    assertThat(attestationsForValidator1).hasSize(2);

    final List<SignedAttestation> attestationsForValidator2 = fetchAttestations(2);
    assertThat(attestationsForValidator2).hasSize(1);
  }

  @Test
  void watermarkIsNotMovedLower() {
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 5, 1));
    insertValidatorAndCreateSlashingData(
        slashingProtectionContext.getRegisteredValidators(), 10, 10, 1);
    jdbi.useTransaction(
        h -> {
          lowWatermarkDao.updateSlotWatermarkFor(h, 1, UInt64.valueOf(8));
          lowWatermarkDao.updateEpochWatermarksFor(h, 1, UInt64.valueOf(8), UInt64.valueOf(8));
        });
    slashingProtectionContext.getPruner().prune();

    // we are only able to prune 2 entries because the watermark is at 8
    assertThat(fetchAttestations(1)).hasSize(2);
    assertThat(fetchBlocks(1)).hasSize(2);
    assertThat(getWatermark(1).getSlot()).isEqualTo(UInt64.valueOf(8));
  }

  @Test
  void lowWatermarkCanMoveToEqualHighWatermark() {
    // in the extreme case where we only keep 1 epoch, the low watermark may move to match the high
    // watermark
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 1, 1));
    insertValidatorAndCreateSlashingData(
        slashingProtectionContext.getRegisteredValidators(), 10, 10, 1);
    MetadataDao metadataDao = new MetadataDao();
    jdbi.useTransaction(
        h -> {
          lowWatermarkDao.updateSlotWatermarkFor(h, 1, UInt64.valueOf(8));
          lowWatermarkDao.updateEpochWatermarksFor(h, 1, UInt64.valueOf(8), UInt64.valueOf(8));
          metadataDao.updateHighWatermark(
              h, new HighWatermark(UInt64.valueOf(9), UInt64.valueOf(9)));
        });
    slashingProtectionContext.getPruner().prune();

    assertThat(fetchAttestations(1)).hasSize(1);
    assertThat(fetchBlocks(1)).hasSize(1);
    assertThat(getWatermark(1).getSlot()).isEqualTo(UInt64.valueOf(9));
  }

  @Test
  void noPruningOccursWhenThereIsNoWatermark() {
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 1, 1));
    slashingProtectionContext.getRegisteredValidators().registerValidators(List.of(Bytes.of(1)));
    for (int i = 0; i < 5; i++) {
      insertBlockAt(UInt64.valueOf(i), 1);
    }
    for (int i = 0; i < 5; i++) {
      insertAttestationAt(UInt64.valueOf(i), UInt64.valueOf(i), 1);
    }

    slashingProtectionContext.getPruner().prune();
    assertThat(fetchAttestations(1)).hasSize(5);
    assertThat(fetchBlocks(1)).hasSize(5);
  }

  @Test
  void prunesForDataWithGaps() {
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 5, 1));
    slashingProtectionContext.getRegisteredValidators().registerValidators(List.of(Bytes.of(1)));

    for (int i = 0; i < 2; i++) {
      insertAttestationAt(UInt64.valueOf(i), UInt64.valueOf(i + 1), 1);
      insertBlockAt(UInt64.valueOf(i), 1);
    }
    for (int i = 8; i < 10; i++) {
      insertAttestationAt(UInt64.valueOf(i), UInt64.valueOf(i + 1), 1);
      insertBlockAt(UInt64.valueOf(i), 1);
    }
    jdbi.useTransaction(
        h -> {
          lowWatermarkDao.updateSlotWatermarkFor(h, 1, UInt64.ZERO);
          lowWatermarkDao.updateEpochWatermarksFor(h, 1, UInt64.ZERO, UInt64.ZERO);
        });

    slashingProtectionContext.getPruner().prune();

    assertThat(fetchAttestations(1)).hasSize(2);
    assertThat(fetchBlocks(1)).hasSize(2);
    assertThat(getWatermark(1).getSlot()).isEqualTo(UInt64.valueOf(8));
    assertThat(getWatermark(1).getSourceEpoch()).isEqualTo(UInt64.valueOf(8));
    assertThat(getWatermark(1).getTargetEpoch()).isEqualTo(UInt64.valueOf(9));
  }

  @Test
  void prunesForDataWithGapsAndDoesNotDeleteAllData() {
    final SlashingProtectionContext slashingProtectionContext =
        SlashingProtectionContextFactory.create(
            new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 5, 1));
    slashingProtectionContext.getRegisteredValidators().registerValidators(List.of(Bytes.of(1)));

    for (int i = 0; i < 2; i++) {
      insertAttestationAt(UInt64.valueOf(i), UInt64.valueOf(i + 1), 1);
      insertBlockAt(UInt64.valueOf(i), 1);
    }
    insertAttestationAt(UInt64.valueOf(9), UInt64.valueOf(9 + 1), 1);
    insertBlockAt(UInt64.valueOf(9), 1);
    jdbi.useTransaction(
        h -> {
          lowWatermarkDao.updateSlotWatermarkFor(h, 1, UInt64.ZERO);
          lowWatermarkDao.updateEpochWatermarksFor(h, 1, UInt64.ZERO, UInt64.ZERO);
        });

    slashingProtectionContext.getPruner().prune();

    assertThat(fetchAttestations(1)).hasSize(1);
    assertThat(fetchBlocks(1)).hasSize(1);
    assertThat(getWatermark(1).getSlot()).isEqualTo(UInt64.valueOf(9));
    assertThat(getWatermark(1).getSourceEpoch()).isEqualTo(UInt64.valueOf(9));
    assertThat(getWatermark(1).getTargetEpoch()).isEqualTo(UInt64.valueOf(10));
  }
}
