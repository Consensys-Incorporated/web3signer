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
package tech.pegasys.web3signer.keystorage.postgres;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;
import javax.sql.DataSource;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * Builds the HikariCP-pooled, read-only datasource used to bulk-read keys. Returns the generic
 * {@link DataSource} type (rather than {@link HikariDataSource}) so that modules consuming this
 * factory (e.g. {@code signing}) never need HikariCP on their own compile classpath.
 */
public final class PostgresConnectionFactory {

  private static final String PG_SOCKET_TIMEOUT_PARAM = "socketTimeout";
  private static final long DEFAULT_PG_SOCKET_TIMEOUT_SECONDS = Duration.ofMinutes(5).toSeconds();

  private PostgresConnectionFactory() {}

  public static DataSource createDataSource(
      final String jdbcUrl,
      final String username,
      final String password,
      final Path poolConfigurationFile) {
    final Properties properties = loadProperties(poolConfigurationFile);
    final String timeoutKey = "dataSource." + PG_SOCKET_TIMEOUT_PARAM;
    if (!properties.containsKey(timeoutKey)) {
      properties.put(timeoutKey, String.valueOf(DEFAULT_PG_SOCKET_TIMEOUT_SECONDS));
    }

    final HikariConfig config = new HikariConfig(properties);
    config.setJdbcUrl(jdbcUrl);
    if (username != null && !username.isEmpty()) {
      config.setUsername(username);
    }
    if (password != null && !password.isEmpty()) {
      config.setPassword(password);
    }
    // this datasource is only ever used for the bulk read-only key scan
    config.setReadOnly(true);

    return new HikariDataSource(config);
  }

  private static Properties loadProperties(final Path configurationFile) {
    final Properties properties = new Properties();
    if (configurationFile != null) {
      try (final FileInputStream inputStream = new FileInputStream(configurationFile.toFile())) {
        properties.load(inputStream);
      } catch (final IOException e) {
        throw new UncheckedIOException(
            "Unable to read Postgres keystore pool configuration file: " + configurationFile, e);
      }
    }
    return properties;
  }
}
