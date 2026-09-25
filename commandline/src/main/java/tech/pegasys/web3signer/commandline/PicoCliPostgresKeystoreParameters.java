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

import tech.pegasys.web3signer.signing.config.PostgresKeystoreParameters;

import java.nio.file.Path;
import java.time.Duration;

import picocli.CommandLine.Option;

public class PicoCliPostgresKeystoreParameters implements PostgresKeystoreParameters {

  public static final String POSTGRES_KEYSTORE_ENABLED_OPTION = "--postgres-keystore-enabled";
  public static final String POSTGRES_KEYSTORE_DB_URL_OPTION = "--postgres-keystore-db-url";
  public static final String POSTGRES_KEYSTORE_DB_USERNAME_OPTION =
      "--postgres-keystore-db-username";
  public static final String POSTGRES_KEYSTORE_DB_PASSWORD_OPTION =
      "--postgres-keystore-db-password";
  public static final String POSTGRES_KEYSTORE_DB_POOL_CONFIG_FILE_OPTION =
      "--postgres-keystore-db-pool-configuration-file";
  public static final String POSTGRES_KEYSTORE_DEK_CACHE_TTL_MINUTES_OPTION =
      "--postgres-keystore-dek-cache-ttl-minutes";
  public static final String POSTGRES_KEYSTORE_DECRYPTION_PARALLELISM_OPTION =
      "--postgres-keystore-decryption-parallelism";
  public static final String POSTGRES_KEYSTORE_DB_HEALTH_CHECK_TIMEOUT_OPTION =
      "--postgres-keystore-db-health-check-timeout-milliseconds";

  @Option(
      names = POSTGRES_KEYSTORE_ENABLED_OPTION,
      description =
          "Set to true to enable bulk loading of BLS keys from a PostgreSQL database."
              + " (Default: ${DEFAULT-VALUE})",
      paramLabel = "<BOOL>",
      arity = "1")
  private boolean enabled = false;

  @Option(
      names = POSTGRES_KEYSTORE_DB_URL_OPTION,
      description = "The jdbc url to use to connect to the postgres keystore database",
      paramLabel = "<jdbc url>")
  private String dbUrl;

  @Option(
      names = POSTGRES_KEYSTORE_DB_USERNAME_OPTION,
      description = "The username to use when connecting to the postgres keystore database",
      paramLabel = "<jdbc user>")
  private String dbUsername;

  @Option(
      names = POSTGRES_KEYSTORE_DB_PASSWORD_OPTION,
      description = "The password to use when connecting to the postgres keystore database",
      paramLabel = "<jdbc password>")
  private String dbPassword;

  @Option(
      names = POSTGRES_KEYSTORE_DB_POOL_CONFIG_FILE_OPTION,
      description = "Optional configuration file for Hikari database connection pool.",
      paramLabel = "<hikari configuration properties file>")
  private Path dbPoolConfigurationFile;

  @Option(
      names = POSTGRES_KEYSTORE_DEK_CACHE_TTL_MINUTES_OPTION,
      description =
          "Minutes to cache a tenant's resolved DEK before re-resolving it via the vault."
              + " (Default: ${DEFAULT-VALUE})",
      paramLabel = "<MINUTES>")
  private long dekCacheTtlMinutes = 15;

  @Option(
      names = POSTGRES_KEYSTORE_DECRYPTION_PARALLELISM_OPTION,
      description =
          "Number of threads used to decrypt keys in parallel. (Default: ${DEFAULT-VALUE})",
      paramLabel = "<INT>",
      hidden = true)
  private int decryptionParallelism = 8;

  @Option(
      names = POSTGRES_KEYSTORE_DB_HEALTH_CHECK_TIMEOUT_OPTION,
      description =
          "Number of milliseconds after which the postgres keystore database health check will be"
              + " failed (Default: ${DEFAULT-VALUE})",
      paramLabel = "<timeout in milliseconds>")
  private long dbHealthCheckTimeoutMilliseconds = 3000;

  @Override
  public boolean isEnabled() {
    return enabled;
  }

  @Override
  public String getDbUrl() {
    return dbUrl;
  }

  @Override
  public String getDbUsername() {
    return dbUsername;
  }

  @Override
  public String getDbPassword() {
    return dbPassword;
  }

  @Override
  public Path getDbPoolConfigurationFile() {
    return dbPoolConfigurationFile;
  }

  @Override
  public Duration getDekCacheTtl() {
    return Duration.ofMinutes(dekCacheTtlMinutes);
  }

  @Override
  public int getDecryptionParallelism() {
    return decryptionParallelism;
  }

  @Override
  public long getDbHealthCheckTimeoutMilliseconds() {
    return dbHealthCheckTimeoutMilliseconds;
  }
}
