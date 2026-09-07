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
package tech.pegasys.web3signer.signing.config;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;

import java.util.concurrent.ExecutorService;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AzureKeyVaultFactoryTest {
  final AzureKeyVaultFactory azureKeyVaultFactory = new AzureKeyVaultFactory();
  final long DEFAULT_AZURE_TIMEOUT = 60;

  @AfterEach
  void shutdownExecutor() {
    azureKeyVaultFactory.close();
  }

  @Test
  void executorIsNotCreatedWhenFactoryIsCreated() {
    assertThat(azureKeyVaultFactory.getExecutorServiceCache().get()).isNull();
  }

  @Test
  void createsExecutorWhenUsingClientSecretMode() {
    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.CLIENT_SECRET,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    assertThat(azureKeyVaultFactory.getExecutorServiceCache().get()).isNotNull();
  }

  @Test
  void reusesExecutorWhenUsingClientSecretMode() {
    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.CLIENT_SECRET,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    final ExecutorService executorService = azureKeyVaultFactory.getExecutorServiceCache().get();
    assertThat(executorService).isNotNull();

    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.CLIENT_SECRET,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    final ExecutorService executorService2 = azureKeyVaultFactory.getExecutorServiceCache().get();
    assertThat(executorService).isSameAs(executorService2);
  }

  @Test
  void doesNotCreateExecutorWhenUsingUserAssignedMode() {
    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.USER_ASSIGNED_MANAGED_IDENTITY,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    assertThat(azureKeyVaultFactory.getExecutorServiceCache().get()).isNull();
  }

  @Test
  void doesNotCreateExecutorWhenUsingSystemAssignedMode() {
    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.SYSTEM_ASSIGNED_MANAGED_IDENTITY,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    assertThat(azureKeyVaultFactory.getExecutorServiceCache().get()).isNull();
  }

  @Test
  void closeShutdownsExecutor() {
    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.CLIENT_SECRET,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    final ExecutorService executorService = azureKeyVaultFactory.getExecutorServiceCache().get();
    assertThat(executorService).isNotNull();

    azureKeyVaultFactory.close();
    assertThat(executorService.isShutdown()).isTrue();
    assertThat(azureKeyVaultFactory.getExecutorServiceCache().get()).isNull();
  }

  @Test
  void reusesVaultInstanceForIdenticalParameters() {
    final AzureKeyVault vault1 =
        azureKeyVaultFactory.createAzureKeyVault(
            "clientId",
            "clientSecret",
            "keyVaultName",
            "tenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);
    final AzureKeyVault vault2 =
        azureKeyVaultFactory.createAzureKeyVault(
            "clientId",
            "clientSecret",
            "keyVaultName",
            "tenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);

    assertThat(vault1).isSameAs(vault2);
    assertThat(azureKeyVaultFactory.getVaultCache().size()).isEqualTo(1);
  }

  @Test
  void createsDistinctVaultInstancesWhenClientSecretDiffers() {
    final AzureKeyVault vault1 =
        azureKeyVaultFactory.createAzureKeyVault(
            "clientId",
            "clientSecret",
            "keyVaultName",
            "tenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);
    final AzureKeyVault vault2 =
        azureKeyVaultFactory.createAzureKeyVault(
            "clientId",
            "rotatedClientSecret",
            "keyVaultName",
            "tenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);

    assertThat(vault1).isNotSameAs(vault2);
    assertThat(azureKeyVaultFactory.getVaultCache().size()).isEqualTo(2);
  }

  @Test
  void createsDistinctVaultInstancesWhenKeyVaultNameDiffers() {
    final AzureKeyVault vault1 =
        azureKeyVaultFactory.createAzureKeyVault(
            "clientId",
            "clientSecret",
            "keyVaultName1",
            "tenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);
    final AzureKeyVault vault2 =
        azureKeyVaultFactory.createAzureKeyVault(
            "clientId",
            "clientSecret",
            "keyVaultName2",
            "tenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);

    assertThat(vault1).isNotSameAs(vault2);
  }

  @Test
  void vaultCacheIsBoundedInSize() {
    for (int i = 0; i < 50; i++) {
      azureKeyVaultFactory.createAzureKeyVault(
          "clientId" + i,
          "clientSecret",
          "keyVaultName",
          "tenantId",
          AzureAuthenticationMode.CLIENT_SECRET,
          DEFAULT_AZURE_TIMEOUT,
          AzureOverrides.NONE);
    }

    assertThat(azureKeyVaultFactory.getVaultCache().size()).isLessThanOrEqualTo(10);
  }

  @Test
  void closeInvalidatesVaultCache() {
    azureKeyVaultFactory.createAzureKeyVault(
        "clientId",
        "clientSecret",
        "keyVaultName",
        "tenantId",
        AzureAuthenticationMode.CLIENT_SECRET,
        DEFAULT_AZURE_TIMEOUT,
        AzureOverrides.NONE);
    assertThat(azureKeyVaultFactory.getVaultCache().size()).isEqualTo(1);

    azureKeyVaultFactory.close();
    assertThat(azureKeyVaultFactory.getVaultCache().size()).isEqualTo(0);
  }

  @Test
  void azureKeyVaultKeyToStringMasksClientSecret() {
    final AzureKeyVaultFactory.AzureKeyVaultKey keyWithSecret =
        new AzureKeyVaultFactory.AzureKeyVaultKey(
            "myClientId",
            "superSecretValue",
            "myVault",
            "myTenantId",
            AzureAuthenticationMode.CLIENT_SECRET,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);
    assertThat(keyWithSecret.toString())
        .contains("clientId=myClientId")
        .contains("clientSecret=***")
        .doesNotContain("superSecretValue")
        .contains("keyVaultName=myVault")
        .contains("tenantId=myTenantId");

    final AzureKeyVaultFactory.AzureKeyVaultKey keyWithNullSecret =
        new AzureKeyVaultFactory.AzureKeyVaultKey(
            "myClientId",
            null,
            "myVault",
            "myTenantId",
            AzureAuthenticationMode.SYSTEM_ASSIGNED_MANAGED_IDENTITY,
            DEFAULT_AZURE_TIMEOUT,
            AzureOverrides.NONE);
    assertThat(keyWithNullSecret.toString()).contains("clientSecret=null");
  }
}
