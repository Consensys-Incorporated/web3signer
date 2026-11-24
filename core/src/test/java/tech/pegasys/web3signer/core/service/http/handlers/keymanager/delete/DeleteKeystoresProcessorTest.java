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
package tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import tech.pegasys.web3signer.BLSTestUtil;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.ValidatorManager;
import tech.pegasys.web3signer.slashingprotection.SlashingProtection;
import tech.pegasys.web3signer.slashingprotection.interchange.IncrementalExporter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DeleteKeystoresProcessorTest {

  static final String PUBLIC_KEY1 = BLSTestUtil.randomKeyPair(1).getPublicKey().toString();
  static final String PUBLIC_KEY2 = BLSTestUtil.randomKeyPair(2).getPublicKey().toString();

  @Mock SlashingProtection slashingProtection;
  @Mock ArtifactSignerProvider artifactSignerProvider;
  @Mock BlsArtifactSigner signer;
  @Mock IncrementalExporter incrementalExporter;
  @Mock ValidatorManager validatorManager;

  DeleteKeystoresProcessor processor;

  @BeforeEach
  void setup() {
    processor =
        new DeleteKeystoresProcessor(
            Optional.of(slashingProtection), artifactSignerProvider, validatorManager);
    lenient()
        .when(slashingProtection.createIncrementalExporter(any()))
        .thenReturn(incrementalExporter);
  }

  @Test
  void testSuccess() {
    when(artifactSignerProvider.getSigner(any())).thenReturn(Optional.of(signer));

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1));
    final DeleteKeystoresResponse response = processor.process(requestBody);
    assertThat(response.getData().size()).isEqualTo(1);
    assertThat(response.getData().get(0).getMessage()).isEqualTo("");
    assertThat(response.getData().get(0).getStatus()).isEqualTo(DeleteKeystoreStatus.DELETED);
    verify(validatorManager).deleteValidator(Bytes.fromHexString(PUBLIC_KEY1));
  }

  @Test
  void testSignerNotFound() {
    when(artifactSignerProvider.getSigner(any())).thenReturn(Optional.empty());
    when(slashingProtection.hasSlashingProtectionDataFor(any())).thenReturn(false);

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1));
    final DeleteKeystoresResponse response = processor.process(requestBody);
    assertThat(response.getData().size()).isEqualTo(1);
    assertThat(response.getData().get(0).getMessage()).isEqualTo("");
    assertThat(response.getData().get(0).getStatus()).isEqualTo(DeleteKeystoreStatus.NOT_FOUND);
    verify(slashingProtection, never())
        .updateValidatorEnabledStatus(eq(Bytes.fromHexString(PUBLIC_KEY1)), anyBoolean());
  }

  @Test
  void testSignerNotActive() {
    when(artifactSignerProvider.getSigner(any())).thenReturn(Optional.empty());
    when(slashingProtection.hasSlashingProtectionDataFor(any())).thenReturn(true);

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1));
    final DeleteKeystoresResponse response = processor.process(requestBody);
    assertThat(response.getData().size()).isEqualTo(1);
    assertThat(response.getData().get(0).getMessage()).isEqualTo("");
    assertThat(response.getData().get(0).getStatus()).isEqualTo(DeleteKeystoreStatus.NOT_ACTIVE);
    verify(slashingProtection, never())
        .updateValidatorEnabledStatus(eq(Bytes.fromHexString(PUBLIC_KEY1)), anyBoolean());
  }

  @Test
  void testErrorResponseWhenValidatorManagerThrowsException() {
    when(artifactSignerProvider.getSigner(any())).thenReturn(Optional.of(signer));
    doThrow(new RuntimeException("error")).when(validatorManager).deleteValidator(any());

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1));
    final DeleteKeystoresResponse response = processor.process(requestBody);
    assertThat(response.getData().size()).isEqualTo(1);
    assertThat(response.getData().get(0).getMessage())
        .isEqualTo("Error deleting keystore file: error");
    assertThat(response.getData().get(0).getStatus()).isEqualTo(DeleteKeystoreStatus.ERROR);
  }

  @Test
  void testSlashingExportFailsAllDeletesWhenIncrementalExportFinaliseFails() throws Exception {
    when(artifactSignerProvider.getSigner(any())).thenReturn(Optional.of(signer));
    doThrow(new IOException("db error")).when(incrementalExporter).finalise();

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1, PUBLIC_KEY2));
    final DeleteKeystoresResponse response = processor.process(requestBody);
    assertThat(response.getData().size()).isEqualTo(2);

    // assert that all results have an error
    for (final DeleteKeystoreResult result : response.getData()) {
      assertThat(result.getMessage()).isEqualTo("Error exporting slashing data: db error");
      assertThat(result.getStatus()).isEqualTo(DeleteKeystoreStatus.ERROR);
    }
    verify(validatorManager).deleteValidator(Bytes.fromHexString(PUBLIC_KEY1));
    verify(validatorManager).deleteValidator(Bytes.fromHexString(PUBLIC_KEY2));
  }

  @Test
  void testSlashingExportRethrowsExceptionWhenIncrementalExportCreateFails() {
    final RuntimeException exception = new RuntimeException("db error");
    doThrow(exception).when(slashingProtection).createIncrementalExporter(any());

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1));
    assertThatThrownBy(() -> processor.process(requestBody))
        .hasMessage("Error deleting keystores")
        .hasCause(exception);
  }

  @Test
  void slashingExportFailOnlyAffectsIndividualKeyStore() {
    when(artifactSignerProvider.getSigner(any())).thenReturn(Optional.of(signer));
    doThrow(new RuntimeException("db error")).when(incrementalExporter).export(PUBLIC_KEY1);

    final DeleteKeystoresRequestBody requestBody =
        new DeleteKeystoresRequestBody(List.of(PUBLIC_KEY1, PUBLIC_KEY2));
    final DeleteKeystoresResponse response = processor.process(requestBody);

    final List<DeleteKeystoreResult> results = response.getData();
    assertThat(results.size()).isEqualTo(2);
    assertThat(results.get(0).getMessage()).isEqualTo("Error exporting slashing data: db error");
    assertThat(results.get(0).getStatus()).isEqualTo(DeleteKeystoreStatus.ERROR);
    assertThat(results.get(1).getMessage()).isEqualTo("");
    assertThat(results.get(1).getStatus()).isEqualTo(DeleteKeystoreStatus.DELETED);
  }
}
