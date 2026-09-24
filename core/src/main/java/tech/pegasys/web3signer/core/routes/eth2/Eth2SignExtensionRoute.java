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
import tech.pegasys.web3signer.core.routes.Web3SignerRoute;
import tech.pegasys.web3signer.core.service.http.handlers.signing.SignerForIdentifier;
import tech.pegasys.web3signer.core.service.http.handlers.signing.SigningExtensionHandler;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;

import io.vertx.core.http.HttpMethod;

public class Eth2SignExtensionRoute implements Web3SignerRoute {
  public static final String SIGN_EXT_PATH = "/api/v1/eth2/ext/sign/:identifier";

  private final Context context;
  private final SignerForIdentifier blsSigner;

  public Eth2SignExtensionRoute(final Context context) {
    this.context = context;

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
    context
        .getRouter()
        .route(HttpMethod.POST, SIGN_EXT_PATH)
        .blockingHandler(new SigningExtensionHandler(blsSigner), false);
  }
}
