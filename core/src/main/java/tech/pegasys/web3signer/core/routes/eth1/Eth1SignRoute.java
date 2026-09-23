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
package tech.pegasys.web3signer.core.routes.eth1;

import static tech.pegasys.web3signer.signing.KeyType.SECP256K1;

import tech.pegasys.web3signer.core.Context;
import tech.pegasys.web3signer.core.routes.Web3SignerRoute;
import tech.pegasys.web3signer.core.service.http.handlers.signing.Eth1SignForIdentifierHandler;
import tech.pegasys.web3signer.core.service.http.handlers.signing.SignerForIdentifier;
import tech.pegasys.web3signer.core.service.http.metrics.HttpApiMetrics;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.config.DefaultArtifactSignerProvider;

import java.util.Optional;

import io.vertx.core.http.HttpMethod;

public class Eth1SignRoute implements Web3SignerRoute {
  private static final String SIGN_PATH = "/api/v1/eth1/sign/:identifier";

  private final Context context;
  private final ArtifactSignerProvider signerProvider;
  private final SignerForIdentifier secpSigner;

  public Eth1SignRoute(final Context context) {
    this.context = context;

    // we need signerProvider which is an instance of DefaultArtifactSignerProvider
    final Optional<ArtifactSignerProvider> first =
        context.getArtifactSignerProviders().stream()
            .filter(provider -> provider instanceof DefaultArtifactSignerProvider)
            .findFirst();

    if (first.isPresent()) {
      signerProvider = first.get();
      secpSigner = new SignerForIdentifier(signerProvider);
    } else {
      throw new IllegalStateException(
          "No DefaultArtifactSignerProvider found in Context for eth1 mode");
    }
  }

  @Override
  public void register() {
    context
        .getRouter()
        .route(HttpMethod.POST, SIGN_PATH)
        .blockingHandler(
            new Eth1SignForIdentifierHandler(
                secpSigner,
                new HttpApiMetrics(context.getMetricsSystem(), SECP256K1, signerProvider)),
            false)
        .failureHandler(context.getErrorHandler());
  }
}
