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
import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.RequestSignatureBody;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;

import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.apache.tuweni.bytes.Bytes32;

public class CommitBoostRequestSignatureHandler implements Handler<RoutingContext> {
  private static final ObjectMapper JSON_MAPPER = SigningObjectMapperFactory.createObjectMapper();

  private final CommitBoostSignerProvider commitBoostSigner;
  private final SigningRootGenerator signingRootGenerator;

  public CommitBoostRequestSignatureHandler(
      final ArtifactSignerProvider artifactSignerProvider, final Spec eth2Spec) {
    commitBoostSigner = new CommitBoostSignerProvider(artifactSignerProvider);
    signingRootGenerator = new SigningRootGenerator(eth2Spec);
  }

  @Override
  public void handle(final RoutingContext context) {
    final String body = context.body().asString();

    // read and validate incoming json body
    final RequestSignatureBody requestSignatureBody;
    try {
      requestSignatureBody = JSON_MAPPER.readValue(body, RequestSignatureBody.class);
    } catch (final JsonProcessingException | IllegalArgumentException e) {
      context.fail(HTTP_BAD_REQUEST);
      return;
    }
    try {
      // Check for pubkey based on signing type, if not exist, fail with 404
      final String identifier = normaliseIdentifier(requestSignatureBody.publicKey());
      if (!commitBoostSigner.isSignerAvailable(identifier, requestSignatureBody.type())) {
        context.fail(HTTP_NOT_FOUND, new ErrorResponseException("Unknown pubkey"));
        return;
      }

      // Calculate Signing root and sign the request
      final Bytes32 signingRoot =
          signingRootGenerator.computeSigningRoot(requestSignatureBody.objectRoot());
      final Optional<String> optionalSig =
          commitBoostSigner.sign(identifier, requestSignatureBody.type(), signingRoot);
      if (optionalSig.isEmpty()) {
        context.fail(HTTP_NOT_FOUND, new ErrorResponseException("Unknown pubkey"));
        return;
      }

      // Encode and send response
      final String jsonEncoded = JSON_MAPPER.writeValueAsString(optionalSig.get());
      context.response().putHeader(CONTENT_TYPE, JSON_UTF_8).end(jsonEncoded);
    } catch (final Exception e) {
      context.fail(HTTP_INTERNAL_ERROR, new ErrorResponseException("Internal Error", e));
    }
  }
}
