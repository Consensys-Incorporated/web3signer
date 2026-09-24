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
import tech.pegasys.web3signer.core.service.http.handlers.HighWatermarkHandler;
import tech.pegasys.web3signer.slashingprotection.SlashingProtectionContext;

import java.util.Optional;

import io.vertx.core.http.HttpMethod;

public class HighWatermarkRoute implements Web3SignerRoute {
  public static final String HIGH_WATERMARK_PATH = "/api/v1/eth2/highWatermark";
  private final Context context;
  private final Optional<SlashingProtectionContext> slashingProtectionContext;

  public HighWatermarkRoute(
      final Context context, final Optional<SlashingProtectionContext> slashingProtectionContext) {
    this.context = context;
    this.slashingProtectionContext = slashingProtectionContext;
  }

  @Override
  public void register() {
    slashingProtectionContext.ifPresent(
        protectionContext ->
            context
                .getRouter()
                .route(HttpMethod.GET, HIGH_WATERMARK_PATH)
                .handler(new HighWatermarkHandler(protectionContext.getSlashingProtection())));
  }
}
