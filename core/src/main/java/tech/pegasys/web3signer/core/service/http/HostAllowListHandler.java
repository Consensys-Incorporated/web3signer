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
package tech.pegasys.web3signer.core.service.http;

import static java.net.HttpURLConnection.HTTP_FORBIDDEN;

import tech.pegasys.web3signer.core.service.http.handlers.ErrorResponseException;

import java.util.List;
import java.util.Optional;

import io.vertx.core.Handler;
import io.vertx.core.net.HostAndPort;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HostAllowListHandler implements Handler<RoutingContext> {
  private static final Logger LOG = LogManager.getLogger();
  private final List<String> httpHostAllowList;

  public HostAllowListHandler(final List<String> httpHostAllowList) {
    this.httpHostAllowList = httpHostAllowList;
  }

  @Override
  public void handle(final RoutingContext event) {
    final Optional<String> hostHeader = getAndValidateHostHeader(event);
    if (httpHostAllowList.contains("*")
        || (hostHeader.isPresent() && hostIsInAllowlist(hostHeader.get()))) {
      event.next();
    } else {
      event.fail(HTTP_FORBIDDEN, new ErrorResponseException("Host not authorized."));
    }
  }

  private Optional<String> getAndValidateHostHeader(final RoutingContext event) {
    final HostAndPort hostAndPort = event.request().authority();
    return Optional.ofNullable(hostAndPort).map(HostAndPort::host);
  }

  private boolean hostIsInAllowlist(final String hostHeader) {
    if (httpHostAllowList.stream()
        .anyMatch(allowlistEntry -> allowlistEntry.equalsIgnoreCase(hostHeader))) {
      return true;
    } else {
      LOG.trace("Host not in allowlist: '{}'", hostHeader);
      return false;
    }
  }
}
