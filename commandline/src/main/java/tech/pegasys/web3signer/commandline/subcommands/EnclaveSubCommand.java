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

import tech.pegasys.web3signer.commandline.VersionProvider;
import tech.pegasys.web3signer.enclave.host.DevKeyReleaseBroker;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

@Command(
    name = EnclaveSubCommand.COMMAND_NAME,
    description =
        "Experimental: tools for the enclave signer (seal keys, provision an enclave, status,"
            + " benchmark).",
    subcommands = {
      HelpCommand.class,
      EnclaveSealSubCommand.class,
      EnclaveProvisionSubCommand.class,
      EnclaveStatusSubCommand.class,
      EnclaveBenchSubCommand.class
    },
    versionProvider = VersionProvider.class,
    mixinStandardHelpOptions = true)
public class EnclaveSubCommand implements Runnable {
  public static final String COMMAND_NAME = "enclave";

  @Spec private CommandSpec spec;

  @Override
  public void run() {
    spec.commandLine().usage(spec.commandLine().getOut());
  }

  /** Shared plumbing of the enclave tools: exit codes, errors, option checks. */
  abstract static class Tool implements Callable<Integer> {
    @Spec CommandSpec spec;

    PrintWriter out() {
      return spec.commandLine().getOut();
    }

    abstract int execute() throws Exception;

    @Override
    public Integer call() {
      try {
        return execute();
      } catch (final ParameterException e) {
        throw e;
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
        spec.commandLine().getErr().println("Interrupted");
        return 1;
      } catch (final Exception e) {
        spec.commandLine()
            .getErr()
            .println("Error: " + (e.getMessage() != null ? e.getMessage() : e.toString()));
        return 1;
      }
    }

    EnclaveAddress address(final String value, final String option) {
      if (value == null) {
        throw new ParameterException(spec.commandLine(), option + " is required");
      }
      try {
        return EnclaveAddress.parseConnect(value);
      } catch (final IllegalArgumentException e) {
        throw new ParameterException(spec.commandLine(), e.getMessage());
      }
    }

    <T> T require(final T value, final String option, final String reason) {
      if (value == null) {
        throw new ParameterException(spec.commandLine(), option + " is required " + reason);
      }
      return value;
    }

    DevKeyReleaseBroker devBroker(final Path masterKeyFile) throws IOException {
      return DevKeyReleaseBroker.fromFile(
          require(masterKeyFile, "--dev-master-key-file", "for the dev platform"));
    }
  }
}
