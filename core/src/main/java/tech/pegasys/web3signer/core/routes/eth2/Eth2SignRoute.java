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

import static tech.pegasys.web3signer.signing.KeyType.BLS;

import tech.pegasys.teku.spec.Spec;
import tech.pegasys.web3signer.core.Context;
import tech.pegasys.web3signer.core.metrics.SlashingProtectionMetrics;
import tech.pegasys.web3signer.core.routes.Web3SignerRoute;
import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.core.service.http.handlers.signing.SignerForIdentifier;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.Eth2SignForIdentifierHandler;
import tech.pegasys.web3signer.core.service.http.metrics.HttpApiMetrics;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.slashingprotection.SlashingProtection;
import tech.pegasys.web3signer.slashingprotection.SlashingProtectionContext;

import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.http.HttpMethod;

public class Eth2SignRoute implements Web3SignerRoute {
  private static final String SIGN_PATH = "/api/v1/eth2/sign/:identifier";
  private final Context context;
  private final SignerForIdentifier blsSigner;
  private final ObjectMapper objectMapper = SigningObjectMapperFactory.createObjectMapper();
  private final Spec eth2Spec;
  private final Optional<SlashingProtection> slashingProtection;

  public Eth2SignRoute(
      final Context context,
      final Spec eth2Spec,
      final Optional<SlashingProtectionContext> slashingProtectionContext) {
    this.context = context;
    this.eth2Spec = eth2Spec;
    slashingProtection =
        slashingProtectionContext.map(SlashingProtectionContext::getSlashingProtection);
    // there should be only one ArtifactSignerProvider in eth2 mode at the moment which is of BLS
    // types.
    final ArtifactSignerProvider artifactSignerProvider =
        context.getArtifactSignerProviders().stream()
            .findFirst()
            .orElseThrow(
                () ->
                    new IllegalStateException(
                        "No ArtifactSignerProvider found in Context for eth2 mode"));

    blsSigner = new SignerForIdentifier(artifactSignerProvider);
  }

  @Override
  public void register() {
    // there should be only one ArtifactSignerProvider in eth2 mode at the moment which is of BLS
    // types.
    final ArtifactSignerProvider artifactSignerProvider =
        context.getArtifactSignerProviders().stream().findFirst().orElseThrow();

    context
        .getRouter()
        .route(HttpMethod.POST, SIGN_PATH)
        .blockingHandler(
            new Eth2SignForIdentifierHandler(
                blsSigner,
                new HttpApiMetrics(context.getMetricsSystem(), BLS, artifactSignerProvider),
                new SlashingProtectionMetrics(context.getMetricsSystem()),
                slashingProtection,
                objectMapper,
                eth2Spec),
            false);
  }
}
