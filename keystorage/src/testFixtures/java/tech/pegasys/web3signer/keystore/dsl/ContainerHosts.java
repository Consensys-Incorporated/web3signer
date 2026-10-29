/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.keystore.dsl;

/** Helpers for reaching Testcontainers containers from the test JVM. */
public final class ContainerHosts {

  private ContainerHosts() {}

  /**
   * Maps Testcontainers' {@code getHost()} to a host name that reliably reaches the container's
   * published ports.
   *
   * <p>Docker Desktop's published-port userland proxy commonly only forwards the IPv4 loopback
   * address, while {@code localhost} can resolve to the IPv6 loopback first and fail with
   * connection refused even though the port is reachable over IPv4. Pin {@code localhost} to {@code
   * 127.0.0.1}, which the self-signed certificates in this package also name.
   *
   * @param containerHost the value of {@code container.getHost()}
   * @return {@code 127.0.0.1} for {@code localhost}, otherwise {@code containerHost} unchanged
   */
  public static String reachableHost(final String containerHost) {
    return "localhost".equals(containerHost) ? "127.0.0.1" : containerHost;
  }
}
