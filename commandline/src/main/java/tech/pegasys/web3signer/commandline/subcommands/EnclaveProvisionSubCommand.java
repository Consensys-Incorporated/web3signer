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
import tech.pegasys.web3signer.enclave.host.AwsKmsKeyReleaseBroker;
import tech.pegasys.web3signer.enclave.host.KeyBundle;
import tech.pegasys.web3signer.enclave.host.KeyBundleIo;
import tech.pegasys.web3signer.enclave.host.KeyProvisioner;
import tech.pegasys.web3signer.enclave.host.KeyReleaseBroker;

import java.nio.file.Path;
import java.time.Duration;

import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;

@Command(
    name = "provision",
    description =
        "Load a key bundle into a running enclave signer: get the enclave's evidence, release"
            + " the data key to it, load the keys. Additive.",
    subcommands = {HelpCommand.class},
    mixinStandardHelpOptions = true)
public class EnclaveProvisionSubCommand extends EnclaveSubCommand.Tool {

  @Option(
      names = "--address",
      description = "Enclave signer address: vsock:<cid>:<port> or tcp:<host>:<port>.",
      paramLabel = "<ADDRESS>",
      required = true)
  private String address;

  @Option(
      names = "--bundle",
      description = "Key bundle file written by 'enclave seal'.",
      paramLabel = "<FILE>",
      required = true)
  private Path bundle;

  @Option(
      names = "--aws-region",
      description = "AWS region of the KMS key (bundles sealed for aws-nitro).",
      paramLabel = "<REGION>")
  private String awsRegion;

  @Option(
      names = "--dev-master-key-file",
      description = "File with the master key the bundle was sealed with (dev platform).",
      paramLabel = "<FILE>")
  private Path devMasterKeyFile;

  @Option(
      names = "--wait-seconds",
      description =
          "How long to wait for the enclave signer to answer (default: ${DEFAULT-VALUE}).",
      paramLabel = "<SECONDS>")
  private int waitSeconds = 60;

  @Option(
      names = "--verify-key-policy",
      description =
          "First check that this principal cannot decrypt the data key without the enclave's"
              + " evidence (default: ${DEFAULT-VALUE}).",
      paramLabel = "<BOOL>",
      arity = "1")
  private boolean verifyKeyPolicy = true;

  @Option(
      names = "--response-timeout-seconds",
      description =
          "How long each provisioning response may take, for example while a key release waits"
              + " for approval (default: ${DEFAULT-VALUE}).",
      paramLabel = "<SECONDS>")
  private int responseTimeoutSeconds = 30;

  @Option(
      names = "--Xdump-release-blob",
      description = "Write the key release answer to this file, for parser debugging.",
      paramLabel = "<FILE>",
      hidden = true)
  private Path dumpReleaseBlob;

  @Override
  int execute() throws Exception {
    if (responseTimeoutSeconds < 1) {
      throw new ParameterException(
          spec.commandLine(), "--response-timeout-seconds must be at least 1");
    }
    final EnclaveClient.Options clientOptions =
        new EnclaveClient.Options(1, (int) EnclaveClient.DEFAULT_PROVISIONING_TIMEOUT.toMillis());
    final KeyBundle keyBundle = KeyBundleIo.read(bundle);
    try (KeyReleaseBroker broker = broker(keyBundle);
        EnclaveClient client = EnclaveClient.create(address(address, "--address"), clientOptions)) {
      final KeyProvisioner.Result result =
          KeyProvisioner.provision(
              keyBundle,
              broker,
              client,
              new KeyProvisioner.Options(
                  waitSeconds,
                  Duration.ofSeconds(responseTimeoutSeconds),
                  verifyKeyPolicy,
                  dumpReleaseBlob));
      out()
          .printf(
              "Provisioned %s: %d loaded, %d duplicates, %d rejected of %d; the enclave holds %d"
                  + " keys%n",
              bundle,
              result.load().loaded(),
              result.load().duplicates(),
              result.load().rejected(),
              result.bundleKeys(),
              result.enclaveKeyCount());
      return 0;
    }
  }

  private KeyReleaseBroker broker(final KeyBundle keyBundle) throws java.io.IOException {
    return switch (keyBundle.dek().provider()) {
      case KeyBundle.Dek.PROVIDER_AWS_KMS ->
          AwsKmsKeyReleaseBroker.create(
              require(awsRegion, "--aws-region", "for bundles sealed with AWS KMS"), null);
      case KeyBundle.Dek.PROVIDER_DEV -> devBroker(devMasterKeyFile);
      default ->
          throw new IllegalArgumentException(
              "Unknown key bundle provider: " + keyBundle.dek().provider());
    };
  }
}
