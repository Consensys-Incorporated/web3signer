/*
 * Copyright 2026 Consensys Software Inc.
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

import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.signing.config.PostgresAwsKmsKekParameters;

import java.net.URI;
import java.util.Optional;

import picocli.CommandLine.Option;

/**
 * Credentials used to call AWS KMS to unwrap a tenant's DEK, when bulk loading BLS keys from the
 * postgres keystore. Deliberately separate from {@link PicoCliAwsSecretsManagerParameters} and
 * {@link PicoCliAwsKmsParameters} - "unwrap N specific keys" and "list/sign against an entire
 * vault" are different privilege scopes that may reasonably use different identities.
 */
public class PicoCliPostgresAwsKmsKekParameters implements PostgresAwsKmsKekParameters {

  public static final String POSTGRES_KEYSTORE_AWS_KMS_AUTH_MODE_OPTION =
      "--postgres-keystore-aws-kms-auth-mode";
  public static final String POSTGRES_KEYSTORE_AWS_KMS_ACCESS_KEY_ID_OPTION =
      "--postgres-keystore-aws-kms-access-key-id";
  public static final String POSTGRES_KEYSTORE_AWS_KMS_SECRET_ACCESS_KEY_OPTION =
      "--postgres-keystore-aws-kms-secret-access-key";
  public static final String POSTGRES_KEYSTORE_AWS_KMS_ENDPOINT_OVERRIDE_OPTION =
      "--postgres-keystore-aws-kms-endpoint-override";

  @Option(
      names = POSTGRES_KEYSTORE_AWS_KMS_AUTH_MODE_OPTION,
      description =
          "Authentication mode to use to call AWS KMS when unwrapping postgres keystore DEKs."
              + " Valid Values: [${COMPLETION-CANDIDATES}] (Default: ${DEFAULT-VALUE})",
      paramLabel = "<AUTHENTICATION_MODE>")
  private AwsAuthenticationMode authenticationMode = AwsAuthenticationMode.SPECIFIED;

  @Option(
      names = POSTGRES_KEYSTORE_AWS_KMS_ACCESS_KEY_ID_OPTION,
      description =
          "AWS Access Key Id to authenticate to AWS KMS. Required for SPECIFIED authentication"
              + " mode.",
      paramLabel = "<ACCESS_KEY_ID>")
  private String accessKeyId;

  @Option(
      names = POSTGRES_KEYSTORE_AWS_KMS_SECRET_ACCESS_KEY_OPTION,
      description =
          "AWS Secret Access Key to authenticate to AWS KMS. Required for SPECIFIED authentication"
              + " mode.",
      paramLabel = "<SECRET_ACCESS_KEY>")
  private String secretAccessKey;

  @Option(
      names = POSTGRES_KEYSTORE_AWS_KMS_ENDPOINT_OVERRIDE_OPTION,
      description = "Override the AWS KMS endpoint.",
      paramLabel = "<URI>")
  private Optional<URI> endpointOverride = Optional.empty();

  @Override
  public AwsAuthenticationMode getAuthenticationMode() {
    return authenticationMode;
  }

  @Override
  public String getAccessKeyId() {
    return accessKeyId;
  }

  @Override
  public String getSecretAccessKey() {
    return secretAccessKey;
  }

  @Override
  public Optional<URI> getEndpointOverride() {
    return endpointOverride;
  }
}
