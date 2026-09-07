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
package tech.pegasys.web3signer.signing.config.metadata;

import static tech.pegasys.web3signer.signing.config.AzureAuthenticationMode.USER_ASSIGNED_MANAGED_IDENTITY;

import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AzureAuthenticationMode;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

public class AzureSecretSigningMetadataDeserializer
    extends StdDeserializer<AzureSecretSigningMetadata> {
  private static final String CLIENT_ID = "clientId";
  private static final String CLIENT_SECRET = "clientSecret";
  private static final String TENANT_ID = "tenantId";
  private static final String VAULT_NAME = "vaultName";
  private static final String SECRET_NAME = "secretName";
  private static final String AUTH_MODE = "authenticationMode";
  private static final String KEY_TYPE = "keyType";
  private static final String TIMEOUT = "timeout";
  private static final String ENDPOINT_OVERRIDE = "endpointOverride";
  private static final String AUTHORITY_HOST_OVERRIDE = "authorityHostOverride";
  private static final String TRUST_CERTIFICATE_OVERRIDE = "trustCertificateOverride";

  @SuppressWarnings("Unused")
  public AzureSecretSigningMetadataDeserializer() {
    this(null);
  }

  protected AzureSecretSigningMetadataDeserializer(final Class<?> vc) {
    super(vc);
  }

  @Override
  public AzureSecretSigningMetadata deserialize(
      final JsonParser parser, final DeserializationContext ctxt) throws IOException {
    KeyType keyType = null;
    String clientId = null;
    String clientSecret = null;
    String tenantId = null;
    String vaultName = null;
    String secretName = null;
    long timeout = 60;
    Optional<URI> endpointOverride = Optional.empty();
    Optional<URI> authorityHostOverride = Optional.empty();
    Optional<Path> trustCertificateOverride = Optional.empty();

    AzureAuthenticationMode authenticationMode = null;

    final JsonNode node = parser.getCodec().readTree(parser);

    if (node.get(KEY_TYPE) != null) {
      try {
        keyType = KeyType.valueOf(node.get(KEY_TYPE).asText());
      } catch (final IllegalArgumentException e) {
        throw new JsonMappingException(
            parser, "Error converting " + KEY_TYPE + ": " + e.getMessage());
      }
    }

    if (node.get(AUTH_MODE) != null) {
      try {
        authenticationMode = AzureAuthenticationMode.valueOf(node.get(AUTH_MODE).asText());
      } catch (final IllegalArgumentException e) {
        throw new JsonMappingException(
            parser, "Error converting " + AUTH_MODE + ": " + e.getMessage());
      }
    }

    if (node.get(VAULT_NAME) != null) {
      vaultName = node.get(VAULT_NAME).asText();
    }

    if (node.get(SECRET_NAME) != null) {
      secretName = node.get(SECRET_NAME).asText();
    }

    if (node.get(CLIENT_ID) != null) {
      clientId = node.get(CLIENT_ID).asText();
    }
    if (node.get(TENANT_ID) != null) {
      tenantId = node.get(TENANT_ID).asText();
    }
    if (node.get(CLIENT_SECRET) != null) {
      clientSecret = node.get(CLIENT_SECRET).asText();
    }
    if (node.get(TIMEOUT) != null) {
      timeout = node.get(TIMEOUT).asLong();
    }

    if (node.get(ENDPOINT_OVERRIDE) != null) {
      endpointOverride = Optional.of(URI.create(node.get(ENDPOINT_OVERRIDE).asText()));
    }
    if (node.get(AUTHORITY_HOST_OVERRIDE) != null) {
      authorityHostOverride = Optional.of(URI.create(node.get(AUTHORITY_HOST_OVERRIDE).asText()));
    }
    if (node.get(TRUST_CERTIFICATE_OVERRIDE) != null) {
      trustCertificateOverride =
          Optional.of(Path.of(node.get(TRUST_CERTIFICATE_OVERRIDE).asText()));
    }

    final AzureSecretSigningMetadata azureSecretSigningMetadata =
        new AzureSecretSigningMetadata(
            clientId,
            clientSecret,
            tenantId,
            vaultName,
            secretName,
            authenticationMode,
            keyType,
            timeout,
            new AzureOverrides(endpointOverride, authorityHostOverride, trustCertificateOverride));

    validate(parser, azureSecretSigningMetadata);

    return azureSecretSigningMetadata;
  }

  private void validate(
      final JsonParser parser, final AzureSecretSigningMetadata azureSecretSigningMetadata)
      throws JsonMappingException {
    final List<String> missingParameters = new ArrayList<>();
    // vaultName and secretName are REQUIRED.
    if (azureSecretSigningMetadata.getKeyVaultName() == null) {
      missingParameters.add(VAULT_NAME);
    }
    if (azureSecretSigningMetadata.getSecretName() == null) {
      missingParameters.add(SECRET_NAME);
    }

    // auth mode specific requirements
    if (azureSecretSigningMetadata.getAuthenticationMode()
        == AzureAuthenticationMode.CLIENT_SECRET) {
      if (azureSecretSigningMetadata.getClientId() == null) {
        missingParameters.add(CLIENT_ID);
      }
      if (azureSecretSigningMetadata.getClientSecret() == null) {
        missingParameters.add(CLIENT_SECRET);
      }
      if (azureSecretSigningMetadata.getTenantId() == null) {
        missingParameters.add(TENANT_ID);
      }
    } else if (azureSecretSigningMetadata.getAuthenticationMode()
        == USER_ASSIGNED_MANAGED_IDENTITY) {
      if (azureSecretSigningMetadata.getClientId() == null) {
        missingParameters.add(CLIENT_ID);
      }
    }

    // system-assigned-managed-identity doesn't require any of clientId, clientSecret and tenantId

    if (!missingParameters.isEmpty()) {
      throw new JsonMappingException(
          parser, "Missing values for required parameters: " + String.join(",", missingParameters));
    }
  }
}
