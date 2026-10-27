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
package tech.pegasys.web3signer.commandline;

import tech.pegasys.web3signer.signing.config.GcpSecretManagerParameters;

import java.util.Optional;

import picocli.CommandLine.Option;

public class PicoCliGcpSecretManagerParameters implements GcpSecretManagerParameters {
  public static final String GCP_SECRETS_ENABLED_OPTION = "--gcp-secrets-enabled";
  public static final String GCP_SECRETS_FILTER_OPTION = "--gcp-secrets-filter";
  public static final String GCP_PROJECT_ID_OPTION = "--gcp-project-id";

  @Option(
      names = GCP_SECRETS_ENABLED_OPTION,
      description =
          "Set to true to enable bulk loading from the GCP Secret Manager service."
              + " (Default: ${DEFAULT-VALUE})",
      paramLabel = "<BOOL>")
  private boolean gcpSecretsEnabledOption = false;

  @Option(
      names = {GCP_PROJECT_ID_OPTION},
      description =
          "A globally unique identifier for the GCP project where the secrets are stored.",
      paramLabel = "<GCP_PROJECT_ID>")
  private String projectId;

  @Option(
      names = GCP_SECRETS_FILTER_OPTION,
      description =
          "Filter string for loading secrets into the application, adhering to the rules in "
              + "[List-operation filtering](https://cloud.google.com/secret-manager/docs/filtering). "
              + "Only secrets matching the filter will be loaded. If filter is empty, all secrets from the "
              + "specified project are loaded into the application.")
  private Optional<String> filter = Optional.empty();

  @Override
  public boolean isEnabled() {
    return gcpSecretsEnabledOption;
  }

  @Override
  public String getProjectId() {
    return projectId;
  }

  @Override
  public Optional<String> getFilter() {
    return filter;
  }
}
