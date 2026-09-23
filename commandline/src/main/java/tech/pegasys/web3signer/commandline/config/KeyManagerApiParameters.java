/*
 * Copyright 2025 ConsenSys AG.
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

import tech.pegasys.web3signer.core.config.KeyManagerApiConfig;

import picocli.CommandLine.Option;

public class KeyManagerApiParameters implements KeyManagerApiConfig {
  @Option(
      names = {"--key-manager-api-enabled", "--enable-key-manager-api"},
      paramLabel = "<BOOL>",
      description = "Enable the key manager API to manage key stores (default: ${DEFAULT-VALUE}).",
      arity = "1")
  private boolean isKeyManagerApiEnabled = false;

  @Option(
      names = "--Xkey-manager-skip-keystore-storage",
      description =
          "Skip writing keystores to disk when importing via Key Manager API. "
              + "Keys will only exist in memory and will be lost on restart (default: ${DEFAULT-VALUE}).",
      paramLabel = "<BOOL>",
      arity = "1",
      hidden = true)
  private boolean skipKeystoreStorage = false;

  @Override
  public boolean isKeyManagerApiEnabled() {
    return isKeyManagerApiEnabled;
  }

  @Override
  public boolean skipKeystoreStorage() {
    return skipKeystoreStorage;
  }
}
