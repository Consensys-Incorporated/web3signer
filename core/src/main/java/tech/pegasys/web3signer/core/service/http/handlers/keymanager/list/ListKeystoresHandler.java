/*
 * Copyright 2021 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.http.handlers.keymanager.list;

import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.JSON_UTF_8;

import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.EnclaveBlsArtifactSigner;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

public class ListKeystoresHandler implements Handler<RoutingContext> {
  public static final int SUCCESS = 200;
  public static final int SERVER_ERROR = 500;

  private final ArtifactSignerProvider artifactSignerProvider;
  private final ObjectMapper objectMapper;

  public ListKeystoresHandler(
      final ArtifactSignerProvider artifactSignerProvider, final ObjectMapper objectMapper) {
    this.artifactSignerProvider = artifactSignerProvider;
    this.objectMapper = objectMapper;
  }

  @Override
  public void handle(final RoutingContext context) {
    final List<KeystoreInfo> data =
        artifactSignerProvider.availableIdentifiers().stream()
            .sorted() // arbitrary sorting to make API calls repeatable
            .map(artifactSignerProvider::getSigner)
            .flatMap(Optional::stream)
            .<KeystoreInfo>mapMulti(
                (signer, out) -> {
                  if (signer instanceof BlsArtifactSigner bls) {
                    out.accept(
                        new KeystoreInfo(
                            bls.getIdentifier(), bls.getDerivationPath(), bls.isReadOnlyKey()));
                  } else if (signer instanceof EnclaveBlsArtifactSigner enclave) {
                    out.accept(new KeystoreInfo(enclave.getIdentifier(), null, true));
                  }
                })
            .collect(Collectors.toList());
    final ListKeystoresResponse response = new ListKeystoresResponse(data);
    try {
      context
          .response()
          .putHeader(CONTENT_TYPE, JSON_UTF_8)
          .setStatusCode(SUCCESS)
          .end(objectMapper.writeValueAsString(response));
    } catch (JsonProcessingException e) {
      context.fail(SERVER_ERROR, e);
    }
  }
}
