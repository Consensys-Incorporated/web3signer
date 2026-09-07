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

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;

/**
 * Verifies the applied schema version of the postgres keystore database matches what this version
 * of Web3Signer expects. Migrations are packaged with the distribution but are never run
 * automatically - operators are expected to apply them out-of-band before enabling this feature,
 * mirroring the slashing-protection module's convention.
 */
public final class PostgresKeystoreVersionChecker {

  public static final int EXPECTED_DATABASE_VERSION = 1;

  private PostgresKeystoreVersionChecker() {}

  public static void verifyVersion(final DataSource dataSource) {
    final int actualVersion;
    try (final Connection connection = dataSource.getConnection();
        final Statement statement = connection.createStatement();
        final ResultSet resultSet =
            statement.executeQuery("SELECT version FROM database_version WHERE id = 1")) {
      if (!resultSet.next()) {
        throw new IllegalStateException(
            "Postgres keystore database_version table contains no rows - please run migrations"
                + " and try again.");
      }
      actualVersion = resultSet.getInt("version");
    } catch (final SQLException e) {
      throw new IllegalStateException(
          "Unable to determine Postgres keystore database version - please run migrations and"
              + " try again.",
          e);
    }

    if (actualVersion != EXPECTED_DATABASE_VERSION) {
      throw new IllegalStateException(
          String.format(
              "Postgres keystore database version [%d] does not match expected version [%d] -"
                  + " please run migrations and try again.",
              actualVersion, EXPECTED_DATABASE_VERSION));
    }
  }
}
