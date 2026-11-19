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
package tech.pegasys.web3signer.enclave.signer;

import tech.pegasys.web3signer.enclave.protocol.EnclaveAddress;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.protocol.Transports;

import java.nio.file.Path;

/**
 * Entry point of the enclave signer. The command line is baked into the enclave image; nothing on
 * the wire can change the platform.
 *
 * <pre>
 * --platform=&lt;aws-nitro|dev&gt; --listen=&lt;address&gt; --blst-library=&lt;path&gt; [--max-connections=&lt;n&gt;]
 * </pre>
 */
public final class EnclaveSignerApp {
  private EnclaveSignerApp() {}

  /** Parsed command line. */
  record Arguments(int platform, EnclaveAddress listen, Path blstLibrary, int maxConnections) {

    static Arguments parse(final String[] args) {
      Integer platform = null;
      EnclaveAddress listen = null;
      Path blstLibrary = null;
      int maxConnections = SignerServer.DEFAULT_MAX_CONNECTIONS;
      for (final String arg : args) {
        final int equals = arg.indexOf('=');
        if (!arg.startsWith("--") || equals < 0) {
          throw new IllegalArgumentException("Unexpected argument: " + arg);
        }
        final String value = arg.substring(equals + 1);
        switch (arg.substring(0, equals)) {
          case "--platform" -> platform = Protocol.parsePlatform(value);
          case "--listen" -> listen = EnclaveAddress.parseListen(value);
          case "--blst-library" -> blstLibrary = Path.of(value);
          case "--max-connections" -> {
            maxConnections = Integer.parseInt(value);
            if (maxConnections < 1) {
              throw new IllegalArgumentException("--max-connections must be at least 1");
            }
          }
          default -> throw new IllegalArgumentException("Unknown option: " + arg);
        }
      }
      if (platform == null || listen == null || blstLibrary == null) {
        throw new IllegalArgumentException(
            "Usage: --platform=<aws-nitro|dev> --listen=<address> --blst-library=<path>"
                + " [--max-connections=<n>]");
      }
      return new Arguments(platform, listen, blstLibrary, maxConnections);
    }
  }

  static Attestor attestorFor(final int platform) {
    return switch (platform) {
      case Protocol.PLATFORM_DEV -> new DevAttestor();
      case Protocol.PLATFORM_AWS_NITRO -> new NsmAttestor();
      default ->
          throw new IllegalArgumentException(
              "Unsupported platform: " + Protocol.platformName(platform));
    };
  }

  static String implementationVersion() {
    final String version = EnclaveSignerApp.class.getPackage().getImplementationVersion();
    return version == null ? "unknown" : version;
  }

  public static void main(final String[] args) throws Exception {
    final Arguments arguments;
    try {
      arguments = Arguments.parse(args);
    } catch (final IllegalArgumentException e) {
      Log.warn(e.getMessage());
      System.exit(2);
      return;
    }
    final Blst blst = new Blst(arguments.blstLibrary());
    final SignerServer server =
        new SignerServer(
            Transports.listen(arguments.listen()),
            blst,
            attestorFor(arguments.platform()),
            arguments.platform(),
            arguments.maxConnections(),
            implementationVersion());
    server.start();
    Log.info(
        "enclave signer "
            + implementationVersion()
            + ", platform "
            + Protocol.platformName(arguments.platform())
            + ", "
            + Runtime.getRuntime().availableProcessors()
            + " cpus, listening on "
            + server.address());
    server.awaitTermination();
  }
}
