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
package tech.pegasys.web3signer.commandline.subcommands;

import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.host.EnclaveBenchmark;

import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;

@Command(
    name = "bench",
    description = "Signing benchmark against an enclave signer that holds keys.",
    subcommands = {HelpCommand.class},
    mixinStandardHelpOptions = true)
public class EnclaveBenchSubCommand extends EnclaveSubCommand.Tool {

  @Option(
      names = "--address",
      description = "Enclave signer address: vsock:<cid>:<port> or tcp:<host>:<port>.",
      paramLabel = "<ADDRESS>",
      required = true)
  private String address;

  @Option(
      names = "--connections",
      description = "Largest number of connections to the enclave (default: ${DEFAULT-VALUE}).",
      paramLabel = "<INTEGER>")
  private int connections = EnclaveClient.Options.DEFAULT.connections();

  @Option(
      names = "--callers",
      description = "Threads calling sign (default: ${DEFAULT-VALUE}).",
      paramLabel = "<INTEGER>")
  private int callers = 32;

  @Option(
      names = "--requests",
      description = "Total number of signing requests (default: ${DEFAULT-VALUE}).",
      paramLabel = "<INTEGER>")
  private int requests = 20_000;

  @Option(
      names = "--verify",
      description = "Verify the first 200 signatures (default: ${DEFAULT-VALUE}).",
      paramLabel = "<BOOL>",
      arity = "1")
  private boolean verify = true;

  @Override
  int execute() throws InterruptedException {
    try (EnclaveClient client =
        EnclaveClient.create(
            address(address, "--address"), new EnclaveClient.Options(connections, 10_000))) {
      final EnclaveBenchmark.Result result =
          EnclaveBenchmark.run(
              client, new EnclaveBenchmark.Options(callers, requests, verify), out());
      return result.failures() > 0 || result.verifyFailures() > 0 ? 1 : 0;
    }
  }
}
