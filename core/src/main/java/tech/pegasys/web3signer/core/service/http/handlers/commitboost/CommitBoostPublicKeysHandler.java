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
package tech.pegasys.web3signer.core.service.http.handlers.commitboost;

import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;
import static java.net.HttpURLConnection.HTTP_INTERNAL_ERROR;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.JSON_UTF_8;

import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.core.service.http.handlers.ErrorResponseException;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.PublicKeyMappings;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.PublicKeysResponse;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.KeyType;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

public class CommitBoostPublicKeysHandler implements Handler<RoutingContext> {
  private final ArtifactSignerProvider artifactSignerProvider;
  private final ObjectMapper objectMapper = SigningObjectMapperFactory.createObjectMapper();

  public CommitBoostPublicKeysHandler(final ArtifactSignerProvider artifactSignerProvider) {
    this.artifactSignerProvider = artifactSignerProvider;
  }

  @Override
  public void handle(final RoutingContext context) {
    final PublicKeysResponse publicKeysResponse = toPublicKeysResponse(artifactSignerProvider);
    try {
      final String jsonEncoded = objectMapper.writeValueAsString(publicKeysResponse);
      context.response().putHeader(CONTENT_TYPE, JSON_UTF_8).end(jsonEncoded);
    } catch (final JsonProcessingException e) {
      // this is not meant to happen
      context.fail(HTTP_INTERNAL_ERROR, new ErrorResponseException("Internal Error", e));
    }
  }

  private PublicKeysResponse toPublicKeysResponse(final ArtifactSignerProvider provider) {
    return new PublicKeysResponse(
        provider.availableIdentifiers().stream()
            .map(consensusPubKey -> toPublicKeyMappings(provider, consensusPubKey))
            .collect(Collectors.toList()));
  }

  private static PublicKeyMappings toPublicKeyMappings(
      final ArtifactSignerProvider provider, final String consensusPubKey) {
    final Map<KeyType, Set<String>> proxyIdentifiers =
        provider.getProxyIdentifiers(consensusPubKey);
    final Set<String> proxyBlsPublicKeys = proxyIdentifiers.getOrDefault(KeyType.BLS, Set.of());
    final Set<String> proxyEcdsaPublicKeys =
        proxyIdentifiers.getOrDefault(KeyType.SECP256K1, Set.of());
    return new PublicKeyMappings(consensusPubKey, proxyBlsPublicKeys, proxyEcdsaPublicKeys);
  }
}
