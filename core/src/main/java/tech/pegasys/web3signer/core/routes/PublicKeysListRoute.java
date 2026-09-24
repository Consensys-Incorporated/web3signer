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
package tech.pegasys.web3signer.core.routes;

import tech.pegasys.web3signer.core.Context;
import tech.pegasys.web3signer.core.service.http.handlers.PublicKeysListHandler;

import io.vertx.core.http.HttpMethod;

public class PublicKeysListRoute implements Web3SignerRoute {

  private static final String ETH1_PATH = "/api/v1/eth1/publicKeys";
  private static final String ETH2_PATH = "/api/v1/eth2/publicKeys";

  private final Context context;
  private final String path;

  public PublicKeysListRoute(final Context context, final String mode) {
    this.context = context;
    this.path =
        switch (mode) {
          case "eth1" -> ETH1_PATH;
          case "eth2" -> ETH2_PATH;
          default ->
              throw new IllegalArgumentException("Unsupported mode for Public Key Route: " + mode);
        };
  }

  @Override
  public void register() {
    context
        .getRouter()
        .route(HttpMethod.GET, path)
        .produces(JSON_HEADER)
        .blockingHandler(new PublicKeysListHandler(context.getArtifactSignerProviders()), false);
  }
}
