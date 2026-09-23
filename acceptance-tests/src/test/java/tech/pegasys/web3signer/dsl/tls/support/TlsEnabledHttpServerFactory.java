/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.dsl.tls.support;

import static tech.pegasys.web3signer.dsl.tls.support.CertificateHelpers.populateFingerprintFile;

import tech.pegasys.web3signer.core.service.jsonrpc.Eth1JsonDecoderFactory;
import tech.pegasys.web3signer.core.service.jsonrpc.JsonDecoder;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.HttpResponseFactory;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.JsonRpcErrorHandler;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.JsonRpcHandler;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.RequestMapper;
import tech.pegasys.web3signer.dsl.tls.TlsCertificateDefinition;
import tech.pegasys.web3signer.dsl.utils.MockBalanceReporter;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.google.common.collect.Lists;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.vertx.core.Vertx;
import io.vertx.core.http.ClientAuth;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PfxOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.ResponseContentTypeHandler;
import org.apache.tuweni.net.tls.VertxTrustOptions;

public class TlsEnabledHttpServerFactory {

  private final Vertx vertx;
  private final List<HttpServer> serversCreated = Lists.newArrayList();

  public TlsEnabledHttpServerFactory() {
    this.vertx = Vertx.vertx();
  }

  public void shutdown() {
    serversCreated.forEach(HttpServer::close);
    vertx.close();
  }

  public HttpServer create(
      final TlsCertificateDefinition serverCert,
      final TlsCertificateDefinition acceptedClientCerts,
      final Path workDir) {
    try {

      final Path serverFingerprintFile = workDir.resolve("server_known_clients");
      populateFingerprintFile(serverFingerprintFile, acceptedClientCerts, Optional.empty());

      final HttpServerOptions web3HttpServerOptions = new HttpServerOptions();
      web3HttpServerOptions.setSsl(true);
      web3HttpServerOptions.setClientAuth(ClientAuth.REQUIRED);
      web3HttpServerOptions.setTrustOptions(
          VertxTrustOptions.allowlistClients(serverFingerprintFile));
      web3HttpServerOptions.setPort(0);
      web3HttpServerOptions.setKeyCertOptions(
          new PfxOptions()
              .setPath(serverCert.getPkcs12File().toString())
              .setPassword(serverCert.getPassword()));

      final Router router = Router.router(vertx);
      final JsonDecoder jsonDecoder = Eth1JsonDecoderFactory.create();
      final RequestMapper requestMapper = new RequestMapper(new MockBalanceReporter());
      router
          .route(HttpMethod.POST, "/")
          .produces(HttpHeaderValues.APPLICATION_JSON.toString())
          .handler(ResponseContentTypeHandler.create())
          .handler(BodyHandler.create())
          .failureHandler(new JsonRpcErrorHandler(new HttpResponseFactory()))
          .handler(new JsonRpcHandler(null, requestMapper, jsonDecoder));

      final HttpServer web3ProviderHttpServer = vertx.createHttpServer(web3HttpServerOptions);

      final CompletableFuture<Boolean> serverConfigured = new CompletableFuture<>();
      web3ProviderHttpServer
          .requestHandler(router)
          .listen()
          .onComplete(result -> serverConfigured.complete(true));

      serverConfigured.get();

      serversCreated.add(web3ProviderHttpServer);
      return web3ProviderHttpServer;
    } catch (final KeyStoreException
        | NoSuchAlgorithmException
        | CertificateException
        | IOException
        | ExecutionException
        | InterruptedException e) {
      throw new RuntimeException("Failed to construct a TLS Enabled Server", e);
    }
  }
}
