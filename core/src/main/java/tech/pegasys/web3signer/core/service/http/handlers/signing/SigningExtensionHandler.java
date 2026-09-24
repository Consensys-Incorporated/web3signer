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
package tech.pegasys.web3signer.core.service.http.handlers.signing;

import static java.nio.charset.StandardCharsets.UTF_8;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.JSON_UTF_8;
import static tech.pegasys.web3signer.signing.util.IdentifierUtils.normaliseIdentifier;

import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.core.service.http.handlers.ErrorResponseException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.tuweni.bytes.Bytes;

/** A Signing Extension to sign very specific messages for a given identifier */
public class SigningExtensionHandler implements Handler<RoutingContext> {
  public static final int NOT_FOUND = 404;
  public static final int BAD_REQUEST = 400;
  // custom copy of ObjectMapper that fails on unknown properties.
  private static final ObjectMapper JSON_MAPPER =
      SigningObjectMapperFactory.createObjectMapper()
          .copy()
          .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  private final SignerForIdentifier signerForIdentifier;

  public SigningExtensionHandler(final SignerForIdentifier signerForIdentifier) {
    this.signerForIdentifier = signerForIdentifier;
  }

  @Override
  public void handle(final RoutingContext routingContext) {
    final String identifier = normaliseIdentifier(routingContext.pathParam("identifier"));
    final String body = routingContext.body().asString();

    // validate that we have correct incoming json body
    try {
      JSON_MAPPER.readValue(body, ProofOfValidationBody.class);
    } catch (final JsonProcessingException | IllegalArgumentException e) {
      routingContext.fail(BAD_REQUEST);
      return;
    }

    final Bytes payload = Bytes.wrap(body.getBytes(UTF_8));
    signerForIdentifier
        .sign(identifier, payload)
        .ifPresentOrElse(
            blsSigHex -> respondWithSignature(routingContext, payload, blsSigHex),
            () ->
                routingContext.fail(
                    NOT_FOUND, new ErrorResponseException("Identifier not found.")));
  }

  private void respondWithSignature(
      final RoutingContext routingContext, final Bytes payload, final String blsSigHex) {
    routingContext.response().putHeader("Content-Type", JSON_UTF_8);
    routingContext
        .response()
        .end(
            new JsonObject()
                .put("payload", payload.toBase64String())
                .put("signature", blsSigHex)
                .encode());
  }
}
