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
package tech.pegasys.web3signer.signing.secp256k1.azure;

import static com.google.common.base.Preconditions.checkNotNull;

import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.signing.config.AzureAuthenticationMode;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultFactory;
import tech.pegasys.web3signer.signing.secp256k1.Signer;
import tech.pegasys.web3signer.signing.secp256k1.common.SignerInitializationException;

import java.util.Set;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class AzureKeyVaultSignerFactory {

  public static final String INACCESSIBLE_KEY_ERROR = "Failed to authenticate to vault.";
  public static final String INVALID_KEY_PARAMETERS_ERROR =
      "Keyvault does not contain key with specified parameters";
  public static final String UNSUPPORTED_CURVE_NAME = "Remote key has unsupported curve name";
  private static final String DEPRECATED_CURVE_NAME = "SECP256K1";
  private static final Set<String> SUPPORTED_CURVE_NAMES = Set.of(DEPRECATED_CURVE_NAME, "P-256K");
  private static final Logger LOG = LogManager.getLogger();
  private final AzureKeyVaultFactory azureKeyVaultFactory;

  public AzureKeyVaultSignerFactory(final AzureKeyVaultFactory azureKeyVaultFactory) {
    this.azureKeyVaultFactory = azureKeyVaultFactory;
  }

  public Signer createSigner(final AzureConfig config) {
    checkNotNull(config, "Config must be specified");

    final AzureKeyVault vault;
    try {
      vault =
          azureKeyVaultFactory.createAzureKeyVault(
              config.getClientId(),
              config.getClientSecret(),
              config.getKeyVaultName(),
              config.getTenantId(),
              AzureAuthenticationMode.CLIENT_SECRET,
              config.getTimeout(),
              config.getAzureOverrides());
    } catch (final Exception e) {
      LOG.error("Failed to connect to vault", e);
      throw new SignerInitializationException(INACCESSIBLE_KEY_ERROR, e);
    }

    final CryptographyClient cryptoClient;
    try {
      cryptoClient = vault.fetchKey(config.getKeyName(), config.getKeyVersion());
    } catch (final Exception e) {
      LOG.error("Unable to load key {}", e.getMessage());
      throw new SignerInitializationException(INVALID_KEY_PARAMETERS_ERROR, e);
    }
    final JsonWebKey jsonWebKey = cryptoClient.getKey().getKey();
    final String curveName = jsonWebKey.getCurveName().toString();
    if (!SUPPORTED_CURVE_NAMES.contains(curveName)) {
      LOG.error(
          "Unsupported curve name: {}. Expecting one of {}.", curveName, SUPPORTED_CURVE_NAMES);
      throw new SignerInitializationException(UNSUPPORTED_CURVE_NAME);
    }
    final Bytes rawPublicKey =
        Bytes.concatenate(Bytes.wrap(jsonWebKey.getX()), Bytes.wrap(jsonWebKey.getY()));
    final boolean useDeprecatedCurveName = DEPRECATED_CURVE_NAME.equals(curveName);

    return new AzureKeyVaultSigner(rawPublicKey, true, useDeprecatedCurveName, cryptoClient);
  }
}
