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

import tech.pegasys.teku.spec.Spec;
import tech.pegasys.web3signer.core.Context;
import tech.pegasys.web3signer.core.routes.Web3SignerRoute;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.CommitBoostGenerateProxyKeyHandler;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.config.DefaultArtifactSignerProvider;
import tech.pegasys.web3signer.signing.config.KeystoresParameters;

import io.vertx.core.http.HttpMethod;

public class CommitBoostGenerateProxyKeyRoute implements Web3SignerRoute {
  private static final String PATH = "/signer/v1/generate_proxy_key";
  private final Context context;
  private final ArtifactSignerProvider artifactSignerProvider;
  private final KeystoresParameters commitBoostParameters;
  private final Spec eth2Spec;

  public CommitBoostGenerateProxyKeyRoute(
      final Context context, final KeystoresParameters commitBoostParameters, final Spec eth2Spec) {
    this.context = context;
    this.commitBoostParameters = commitBoostParameters;
    this.eth2Spec = eth2Spec;

    // there should be only one DefaultArtifactSignerProvider in eth2 mode
    artifactSignerProvider =
        context.getArtifactSignerProviders().stream()
            .filter(p -> p instanceof DefaultArtifactSignerProvider)
            .findFirst()
            .orElseThrow();
  }

  @Override
  public void register() {
    context
        .getRouter()
        .route(HttpMethod.POST, PATH)
        .blockingHandler(
            new CommitBoostGenerateProxyKeyHandler(
                artifactSignerProvider, commitBoostParameters, eth2Spec),
            false);
  }
}
