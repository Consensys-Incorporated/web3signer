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
package tech.pegasys.web3signer.slashingprotection.interchange;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import tech.pegasys.web3signer.slashingprotection.dao.LowWatermarkDao;
import tech.pegasys.web3signer.slashingprotection.dao.MetadataDao;
import tech.pegasys.web3signer.slashingprotection.dao.SignedAttestationsDao;
import tech.pegasys.web3signer.slashingprotection.dao.SignedBlocksDao;
import tech.pegasys.web3signer.slashingprotection.dao.SigningWatermark;
import tech.pegasys.web3signer.slashingprotection.dao.Validator;
import tech.pegasys.web3signer.slashingprotection.dao.ValidatorsDao;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonGenerator;
import db.DatabaseUtil;
import org.apache.tuweni.bytes.Bytes;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class InterchangeV5ExporterTest {

  @Mock private ValidatorsDao validatorsDao;
  @Mock private SignedBlocksDao signedBlocksDao;
  @Mock private SignedAttestationsDao signedAttestationsDao;
  @Mock private MetadataDao metadataDao;
  @Mock private LowWatermarkDao lowWatermarkDao;

  private static final String PUBLIC_KEY = "0x01";

  @Test
  public void populateInterchangeDataThrowsUncheckedIOException() {
    final DatabaseUtil.TestDatabaseInfo testDatabaseInfo = DatabaseUtil.createWithoutMigration();
    final Jdbi jdbi = testDatabaseInfo.jdbi();
    final InterchangeV5Exporter exporter =
        new InterchangeV5Exporter(
            jdbi,
            validatorsDao,
            signedBlocksDao,
            signedAttestationsDao,
            metadataDao,
            lowWatermarkDao);
    final Validator validator = new Validator(1, Bytes.fromHexString(PUBLIC_KEY));
    when(validatorsDao.retrieveValidators(any(), any())).thenReturn(List.of(validator));
    when(lowWatermarkDao.findLowWatermarkForValidator(any(), eq(1)))
        .thenReturn(Optional.of(new SigningWatermark()));
    // throw exception as the defaultAnswer as we don't care which json method is the cause
    final JsonGenerator mockJsonGenerator =
        mock(
            JsonGenerator.class,
            __ -> {
              throw new IOException("fake json error");
            });

    assertThatThrownBy(() -> exporter.populateInterchangeData(mockJsonGenerator, PUBLIC_KEY))
        .isInstanceOf(UncheckedIOException.class)
        .hasMessage("Failed to construct a validator entry in json")
        .hasRootCauseMessage("fake json error");
  }
}
