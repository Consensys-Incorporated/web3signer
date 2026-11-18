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

import tech.pegasys.web3signer.enclave.host.AwsKmsKeyReleaseBroker;
import tech.pegasys.web3signer.enclave.host.KeyReleaseBroker;
import tech.pegasys.web3signer.enclave.host.KeySealer;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.nio.file.Path;

import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;

@Command(
    name = "seal",
    description =
        "Encrypt BLS keys into a key bundle for the enclave signer. Runs on the operator's machine.",
    subcommands = {HelpCommand.class},
    mixinStandardHelpOptions = true)
public class EnclaveSealSubCommand extends EnclaveSubCommand.Tool {

  @Option(
      names = "--platform",
      description =
          "Enclave platform the bundle is for: aws-nitro or dev (default: ${DEFAULT-VALUE}).",
      paramLabel = "<PLATFORM>")
  private String platform = "aws-nitro";

  @Option(
      names = "--aws-region",
      description = "AWS region of the KMS key (aws-nitro).",
      paramLabel = "<REGION>")
  private String awsRegion;

  @Option(
      names = "--aws-kms-key-id",
      description = "KMS key id, ARN or alias that wraps the data key (aws-nitro).",
      paramLabel = "<KEY_ID>")
  private String awsKmsKeyId;

  @Option(
      names = "--dev-master-key-file",
      description = "File with a 64 hex character master key (dev platform, insecure).",
      paramLabel = "<FILE>")
  private Path devMasterKeyFile;

  @Option(
      names = "--keystores-path",
      description = "Directory of EIP-2335 keystores (*.json) to seal.",
      paramLabel = "<DIRECTORY>")
  private Path keystoresPath;

  @Option(
      names = "--keystores-password-file",
      description = "File with the password of every keystore.",
      paramLabel = "<FILE>")
  private Path keystoresPasswordFile;

  @Option(
      names = "--keystores-passwords-path",
      description = "Directory with one <keystore name>.txt password file per keystore.",
      paramLabel = "<DIRECTORY>")
  private Path keystoresPasswordsPath;

  @Option(
      names = "--raw-keys-file",
      description = "File with one hex encoded 32-byte BLS secret per line. For test keys.",
      paramLabel = "<FILE>")
  private Path rawKeysFile;

  @Option(
      names = "--output",
      description = "Key bundle file to write.",
      paramLabel = "<FILE>",
      required = true)
  private Path output;

  @Override
  int execute() throws Exception {
    final int target = Protocol.parsePlatform(platform);
    try (KeyReleaseBroker broker =
        target == Protocol.PLATFORM_AWS_NITRO
            ? AwsKmsKeyReleaseBroker.create(
                require(awsRegion, "--aws-region", "for aws-nitro"),
                require(awsKmsKeyId, "--aws-kms-key-id", "for aws-nitro"))
            : devBroker(devMasterKeyFile)) {
      final KeySealer.Result result =
          KeySealer.sealToFile(
              new KeySealer.Sources(
                  keystoresPath, keystoresPasswordFile, keystoresPasswordsPath, rawKeysFile),
              broker,
              output);
      out().printf("Sealed %d keys under %s into %s%n", result.keyCount(), result.keyId(), output);
      return 0;
    }
  }
}
