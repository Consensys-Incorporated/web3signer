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
package tech.pegasys.web3signer.commandline;

import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.signing.config.AzureAuthenticationMode;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultParameters;

import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import picocli.CommandLine;
import picocli.CommandLine.Option;

public class PicoCliAzureKeyVaultParameters implements AzureKeyVaultParameters {

  public static final String AZURE_ENDPOINT_OVERRIDE_OPTION = "--Xazure-endpoint-override";
  public static final String AZURE_AUTHORITY_HOST_OVERRIDE_OPTION =
      "--Xazure-authority-host-override";
  public static final String AZURE_TRUST_CERTIFICATE_OVERRIDE_OPTION =
      "--Xazure-trust-certificate-override";

  @Option(
      names = {"--azure-vault-enabled"},
      description =
          "Set true if Web3signer should try and load all keys in the specified vault "
              + "(Default: ${DEFAULT-VALUE})",
      paramLabel = "<BOOL>")
  private boolean azureKeyVaultEnabled = false;

  @Option(
      names = {"--azure-vault-auth-mode"},
      description =
          "Authentication mode for Azure Vault. Valid Values: [${COMPLETION-CANDIDATES}]"
              + " (Default: ${DEFAULT-VALUE})",
      paramLabel = "<AUTHENTICATION_MODE>")
  private AzureAuthenticationMode authenticationMode = AzureAuthenticationMode.CLIENT_SECRET;

  @Option(
      names = {"--azure-vault-name"},
      description = "Name of the vault to access - used as the sub-domain to vault.azure.net",
      paramLabel = "<KEY_VAULT_NAME>")
  private String keyVaultName;

  @Option(
      names = {"--azure-client-id"},
      description =
          "The ID used by client secret or user-assigned managed identity authentication mode to access Azure key vault. "
              + "Optional for system-assigned managed identity.",
      paramLabel = "<CLIENT_ID>")
  private String clientId;

  @Option(
      names = {"--azure-tenant-id"},
      description = "The unique identifier of the Azure Portal instance being used",
      paramLabel = "<TENANT_ID>")
  private String tenantId;

  @Option(
      names = {"--azure-client-secret"},
      description = "The secret used to access the vault (along with client-id)",
      paramLabel = "<CLIENT_SECRET>")
  private String clientSecret;

  @Option(
      names = {"--azure-response-timeout"},
      description = "The response timeout to be used by the http client (in seconds)",
      paramLabel = "<AZURE_RESPONSE_TIMEOUT>")
  private long timeout = 60;

  @CommandLine.Option(
      names = {"--azure-tags"},
      mapFallbackValue = "",
      split = "\\|",
      splitSynopsisLabel = "|",
      description = "Optional key-value pair to filter secrets based on tags.",
      paramLabel = "<TAG_NAME>=<TAG_VALUE>")
  private Map<String, String> tags = new LinkedHashMap<>();

  @Option(
      names = {AZURE_ENDPOINT_OVERRIDE_OPTION},
      description = "EXPERIMENTAL: Override Azure Key Vault endpoint.",
      paramLabel = "<URI>",
      hidden = true)
  private Optional<URI> endpointOverride;

  @Option(
      names = {AZURE_AUTHORITY_HOST_OVERRIDE_OPTION},
      description = "EXPERIMENTAL: Override the Microsoft Entra ID (Azure AD) authority host.",
      paramLabel = "<URI>",
      hidden = true)
  private Optional<URI> authorityHostOverride;

  @Option(
      names = {AZURE_TRUST_CERTIFICATE_OVERRIDE_OPTION},
      description =
          "EXPERIMENTAL: Trust the given X.509 certificate file for TLS connections to the "
              + "Azure Key Vault endpoint and Microsoft Entra ID authority, in place of the "
              + "platform default trust store.",
      paramLabel = "<FILE>",
      hidden = true)
  private Optional<Path> trustCertificateOverride;

  @Override
  public boolean isAzureKeyVaultEnabled() {
    return azureKeyVaultEnabled;
  }

  @Override
  public AzureAuthenticationMode getAuthenticationMode() {
    return authenticationMode;
  }

  @Override
  public String getKeyVaultName() {
    return keyVaultName;
  }

  @Override
  public String getTenantId() {
    return tenantId;
  }

  @Override
  public String getClientId() {
    return clientId;
  }

  @Override
  public String getClientSecret() {
    return clientSecret;
  }

  @Override
  public long getTimeout() {
    return timeout;
  }

  @Override
  public Map<String, String> getTags() {
    return tags;
  }

  @Override
  public AzureOverrides getAzureOverrides() {
    return new AzureOverrides(endpointOverride, authorityHostOverride, trustCertificateOverride);
  }
}
