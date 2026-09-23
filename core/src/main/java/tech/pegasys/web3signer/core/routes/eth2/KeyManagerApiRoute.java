/*
 * Copyright 2024 ConsenSys AG.
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
package tech.pegasys.web3signer.core.routes.eth2;

import tech.pegasys.web3signer.core.Context;
import tech.pegasys.web3signer.core.config.BaseConfig;
import tech.pegasys.web3signer.core.config.KeyManagerApiConfig;
import tech.pegasys.web3signer.core.routes.Web3SignerRoute;
import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete.DeleteKeystoresHandler;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.imports.ImportKeystoresHandler;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.list.ListKeystoresHandler;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.DefaultValidatorManager;
import tech.pegasys.web3signer.signing.KeystoreFileManager;
import tech.pegasys.web3signer.signing.ValidatorManager;
import tech.pegasys.web3signer.signing.config.metadata.parser.YamlMapperFactory;
import tech.pegasys.web3signer.slashingprotection.DbValidatorManager;
import tech.pegasys.web3signer.slashingprotection.SlashingProtection;
import tech.pegasys.web3signer.slashingprotection.SlashingProtectionContext;
import tech.pegasys.web3signer.slashingprotection.dao.ValidatorsDao;

import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.http.HttpMethod;

public class KeyManagerApiRoute implements Web3SignerRoute {
  public static final String KEYSTORES_PATH = "/eth/v1/keystores";
  private final Context context;
  private final ArtifactSignerProvider blsSignerProvider;
  private final Optional<SlashingProtectionContext> slashingProtectionContext;
  private final Optional<SlashingProtection> slashingProtection;
  private final ObjectMapper objectMapper = SigningObjectMapperFactory.createObjectMapper();
  private final BaseConfig baseConfig;
  private final KeyManagerApiConfig keyManagerApiConfig;

  public KeyManagerApiRoute(
      final Context context,
      final BaseConfig baseConfig,
      final KeyManagerApiConfig keyManagerApiConfig,
      final Optional<SlashingProtectionContext> slashingProtectionContext) {
    this.context = context;
    this.baseConfig = baseConfig;
    this.keyManagerApiConfig = keyManagerApiConfig;
    this.slashingProtectionContext = slashingProtectionContext;

    slashingProtection =
        slashingProtectionContext.map(SlashingProtectionContext::getSlashingProtection);
    // there should be only one ArtifactSignerProvider in eth2 mode at the moment which is of BLS
    // types.
    blsSignerProvider = context.getArtifactSignerProviders().stream().findFirst().orElseThrow();
  }

  @Override
  public void register() {
    registerGet();

    // TODO: should there be separate instance for POST and DELETE?
    final ValidatorManager validatorManager = createValidatorManager();

    registerPost(validatorManager);

    registerDelete(validatorManager);
  }

  private void registerGet() {
    context
        .getRouter()
        .route(HttpMethod.GET, KEYSTORES_PATH)
        .blockingHandler(new ListKeystoresHandler(blsSignerProvider, objectMapper), false)
        .failureHandler(context.getErrorHandler());
  }

  private void registerPost(ValidatorManager validatorManager) {
    context
        .getRouter()
        .route(HttpMethod.POST, KEYSTORES_PATH)
        .blockingHandler(
            new ImportKeystoresHandler(
                objectMapper,
                baseConfig.getKeyConfigPath(),
                slashingProtection,
                blsSignerProvider,
                validatorManager),
            false)
        .failureHandler(context.getErrorHandler());
  }

  private void registerDelete(ValidatorManager validatorManager) {
    context
        .getRouter()
        .route(HttpMethod.DELETE, KEYSTORES_PATH)
        .blockingHandler(
            new DeleteKeystoresHandler(
                objectMapper, slashingProtection, blsSignerProvider, validatorManager),
            false)
        .failureHandler(context.getErrorHandler());
  }

  private ValidatorManager createValidatorManager() {
    final ValidatorManager baseValidatorManager;
    final Optional<KeystoreFileManager> keystoreFileManager;
    if (keyManagerApiConfig.skipKeystoreStorage()) {
      keystoreFileManager = Optional.empty();
    } else {
      keystoreFileManager =
          Optional.of(
              new KeystoreFileManager(
                  baseConfig.getKeyConfigPath(),
                  YamlMapperFactory.createYamlMapper(baseConfig.getKeyStoreConfigFileMaxSize())));
    }
    baseValidatorManager = new DefaultValidatorManager(blsSignerProvider, keystoreFileManager);

    return slashingProtectionContext
        .map(
            ctx ->
                (ValidatorManager)
                    new DbValidatorManager(
                        baseValidatorManager,
                        ctx.getRegisteredValidators(),
                        ctx.getSlashingProtectionJdbi(),
                        new ValidatorsDao()))
        .orElse(baseValidatorManager);
  }
}
