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
package tech.pegasys.web3signer.commandline.config;

import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;
import tech.pegasys.web3signer.signing.config.EnclaveSignerParameters;

import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

/** Experimental: BLS keys held by an enclave signer. All options are hidden. */
public class PicoCliEnclaveSignerParameters implements EnclaveSignerParameters {
  public static final String ENABLED_OPTION = "--Xenclave-signer-enabled";
  public static final String ADDRESS_OPTION = "--Xenclave-signer-address";

  @Spec private CommandSpec commandSpec; // injected by picocli

  @Option(
      names = ENABLED_OPTION,
      description = "Load BLS keys from an enclave signer (default: ${DEFAULT-VALUE}).",
      paramLabel = "<BOOL>",
      arity = "1",
      hidden = true)
  private boolean enabled = false;

  @Option(
      names = ADDRESS_OPTION,
      description = "Address of the enclave signer: vsock:<cid>:<port> or tcp:<host>:<port>.",
      paramLabel = "<ADDRESS>",
      arity = "1",
      hidden = true)
  private String address;

  @Option(
      names = "--Xenclave-signer-connections",
      description =
          "Largest number of connections to the enclave signer, opened on demand"
              + " (default: ${DEFAULT-VALUE}).",
      paramLabel = "<INTEGER>",
      arity = "1",
      hidden = true)
  private int connections = EnclaveClient.Options.DEFAULT.connections();

  @Option(
      names = "--Xenclave-signer-request-timeout-ms",
      description = "Timeout of one enclave signer request (default: ${DEFAULT-VALUE}).",
      paramLabel = "<MILLISECONDS>",
      arity = "1",
      hidden = true)
  private int requestTimeoutMillis = 2000;

  @Override
  public boolean isEnabled() {
    return enabled;
  }

  @Override
  public String getAddress() {
    return address;
  }

  @Override
  public int getConnections() {
    return connections;
  }

  @Override
  public int getRequestTimeoutMillis() {
    return requestTimeoutMillis;
  }

  public void validate() {
    if (!enabled) {
      return;
    }
    if (address == null) {
      throw new ParameterException(
          commandSpec.commandLine(), ENABLED_OPTION + "=true requires " + ADDRESS_OPTION);
    }
    try {
      EnclaveAddress.parseConnect(address);
    } catch (final IllegalArgumentException e) {
      throw new ParameterException(commandSpec.commandLine(), e.getMessage());
    }
    if (connections < 1) {
      throw new ParameterException(
          commandSpec.commandLine(), "--Xenclave-signer-connections must be at least 1");
    }
    if (requestTimeoutMillis < 1) {
      throw new ParameterException(
          commandSpec.commandLine(), "--Xenclave-signer-request-timeout-ms must be at least 1");
    }
  }
}
