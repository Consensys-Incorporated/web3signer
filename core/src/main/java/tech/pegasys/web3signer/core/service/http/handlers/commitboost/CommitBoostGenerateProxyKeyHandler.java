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
import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_INTERNAL_ERROR;
import static java.net.HttpURLConnection.HTTP_NOT_FOUND;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.JSON_UTF_8;
import static tech.pegasys.web3signer.signing.util.IdentifierUtils.normaliseIdentifier;

import tech.pegasys.teku.spec.Spec;
import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.core.service.http.handlers.ErrorResponseException;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.CommitBoostSignRequestType;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.GenerateProxyKeyBody;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.ProxyDelegation;
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.SignedProxyDelegation;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.config.KeystoresParameters;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.apache.tuweni.bytes.Bytes32;

public class CommitBoostGenerateProxyKeyHandler implements Handler<RoutingContext> {
  private static final ObjectMapper JSON_MAPPER = SigningObjectMapperFactory.createObjectMapper();

  private final CommitBoostSignerProvider commitBoostSignerProvider;
  private final ProxyKeysGenerator proxyKeyGenerator;
  private final SigningRootGenerator signingRootGenerator;

  public CommitBoostGenerateProxyKeyHandler(
      final ArtifactSignerProvider artifactSignerProvider,
      final KeystoresParameters commitBoostParameters,
      final Spec eth2Spec) {
    commitBoostSignerProvider = new CommitBoostSignerProvider(artifactSignerProvider);
    proxyKeyGenerator = new ProxyKeysGenerator(commitBoostParameters);
    signingRootGenerator = new SigningRootGenerator(eth2Spec);
  }

  @Override
  public void handle(final RoutingContext context) {
    final String body = context.body().asString();

    // read and validate incoming json body
    final GenerateProxyKeyBody proxyKeyBody;
    try {
      proxyKeyBody = JSON_MAPPER.readValue(body, GenerateProxyKeyBody.class);
    } catch (final JsonProcessingException | IllegalArgumentException e) {
      context.fail(HTTP_BAD_REQUEST);
      return;
    }

    // Check for identifier, if not exist, fail with 404
    final String consensusPubKey = normaliseIdentifier(proxyKeyBody.blsPublicKey());
    final boolean signerAvailable =
        commitBoostSignerProvider.isSignerAvailable(
            consensusPubKey, CommitBoostSignRequestType.CONSENSUS);
    if (!signerAvailable) {
      context.fail(HTTP_NOT_FOUND, new ErrorResponseException("Unknown pubkey"));
      return;
    }

    try {
      // Generate actual proxy key and encrypted keystore based on signature scheme
      final ArtifactSigner proxyArtifactSigner =
          switch (proxyKeyBody.scheme()) {
            case BLS -> proxyKeyGenerator.generateBLSProxyKey(consensusPubKey);
            case ECDSA -> proxyKeyGenerator.generateECProxyKey(consensusPubKey);
          };

      // Add generated proxy ArtifactSigner to ArtifactSignerProvider
      commitBoostSignerProvider.addProxySigner(proxyArtifactSigner, consensusPubKey);

      final ProxyDelegation proxyDelegation =
          new ProxyDelegation(consensusPubKey, proxyArtifactSigner.getIdentifier());
      final Bytes32 signingRoot =
          signingRootGenerator.computeSigningRoot(
              proxyDelegation.toMerkleizable(proxyKeyBody.scheme()).hashTreeRoot());
      final Optional<String> optionalSig =
          commitBoostSignerProvider.sign(
              consensusPubKey, CommitBoostSignRequestType.CONSENSUS, signingRoot);
      if (optionalSig.isEmpty()) {
        context.fail(HTTP_NOT_FOUND, new ErrorResponseException("Unknown pubkey"));
        return;
      }

      final SignedProxyDelegation signedProxyDelegation =
          new SignedProxyDelegation(proxyDelegation, optionalSig.get());

      // Encode and send response
      final String jsonEncoded = JSON_MAPPER.writeValueAsString(signedProxyDelegation);
      context.response().putHeader(CONTENT_TYPE, JSON_UTF_8).end(jsonEncoded);
    } catch (final Exception e) {
      context.fail(HTTP_INTERNAL_ERROR, new ErrorResponseException("Internal Error", e));
    }
  }
}
