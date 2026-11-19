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
package tech.pegasys.web3signer.slashingprotection;

import static db.DatabaseUtil.MIGRATIONS_LOCATION;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.slashingprotection.dao.DatabaseVersionDao;

import db.DatabaseUtil;
import db.DatabaseUtil.TestDatabaseInfo;
import org.flywaydb.core.Flyway;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;

public class DatabaseVersionIntegrationTest {

  public static final String DB_USERNAME = "postgres";
  public static final String DB_PASSWORD = "postgres";

  @Test
  void ensureDatabaseVersionMatchesNumberOfMigrations() {
    final TestDatabaseInfo testDatabaseInfo = DatabaseUtil.create();
    final Flyway flyway =
        Flyway.configure()
            .locations(MIGRATIONS_LOCATION)
            .dataSource(testDatabaseInfo.dataSource())
            .load();
    final int countMigrations = flyway.info().applied().length;

    final DatabaseVersionDao databaseVersionDao = new DatabaseVersionDao();
    final Jdbi jdbi = Jdbi.create(testDatabaseInfo.databaseUrl(), DB_USERNAME, DB_PASSWORD);

    final int reportedVersion = jdbi.withHandle(databaseVersionDao::findDatabaseVersion);

    assertThat(reportedVersion).isEqualTo(countMigrations);
  }
}
