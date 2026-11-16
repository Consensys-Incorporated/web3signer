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

import tech.pegasys.web3signer.enclave.protocol.EnclaveClient;
import tech.pegasys.web3signer.enclave.protocol.EnclaveStatus;
import tech.pegasys.web3signer.enclave.protocol.EnclaveUnavailableException;

import java.util.concurrent.TimeUnit;

import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;

@Command(
    name = "status",
    description =
        "Show the enclave signer's status. Exits non-zero unless it answers and holds at least"
            + " --min-keys keys.",
    subcommands = {HelpCommand.class},
    mixinStandardHelpOptions = true)
public class EnclaveStatusSubCommand extends EnclaveSubCommand.Tool {
  private static final long RETRY_MILLIS = 1000;

  @Option(
      names = "--address",
      description = "Enclave signer address: vsock:<cid>:<port> or tcp:<host>:<port>.",
      paramLabel = "<ADDRESS>",
      required = true)
  private String address;

  @Option(
      names = "--wait-seconds",
      description =
          "Keep asking until the condition holds or this many seconds have passed"
              + " (default: ${DEFAULT-VALUE}).",
      paramLabel = "<SECONDS>")
  private int waitSeconds = 0;

  @Option(
      names = "--min-keys",
      description = "Number of keys the enclave must hold (default: ${DEFAULT-VALUE}).",
      paramLabel = "<INTEGER>")
  private long minKeys = 0;

  @Override
  int execute() throws InterruptedException {
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(waitSeconds);
    try (EnclaveClient client =
        EnclaveClient.create(
            address(address, "--address"), new EnclaveClient.Options(1, 1, 2000))) {
      String problem;
      while (true) {
        try {
          final EnclaveStatus status = client.status();
          if (status.keyCount() >= minKeys) {
            print(status);
            return 0;
          }
          problem =
              "the enclave holds " + status.keyCount() + " keys, expected at least " + minKeys;
        } catch (final EnclaveUnavailableException e) {
          problem = e.getMessage();
        }
        if (System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(RETRY_MILLIS) > deadline) {
          spec.commandLine().getErr().println("Error: " + problem);
          return 1;
        }
        Thread.sleep(RETRY_MILLIS);
      }
    }
  }

  private void print(final EnclaveStatus status) {
    out()
        .printf(
            "address %s%nprotocol version %d%nplatform %s%ncpus %d%nkeys %d%nboot id %s%nversion %s%n",
            address,
            status.protocolVersion(),
            status.platformName(),
            status.cpus(),
            status.keyCount(),
            status.bootId(),
            status.version());
  }
}
