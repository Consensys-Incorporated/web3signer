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

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import javax.sql.DataSource;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;

/** Spins up a real, migrated, embedded postgres keystore database for tests. */
public final class PostgresKeystoreTestUtil {

  public static final String USERNAME = "postgres";
  public static final String PASSWORD = "postgres";
  public static final String MIGRATIONS_LOCATION = "/migrations/keystore-postgresql/";

  private PostgresKeystoreTestUtil() {}

  public static TestDatabase create() {
    try {
      final EmbeddedPostgres db = EmbeddedPostgres.start();
      final String jdbcUrl = String.format("jdbc:postgresql://localhost:%d/postgres", db.getPort());
      final Flyway flyway =
          Flyway.configure()
              .locations(MIGRATIONS_LOCATION)
              .dataSource(db.getPostgresDatabase())
              .load();
      flyway.migrate();
      final DataSource dataSource =
          PostgresConnectionFactory.createDataSource(jdbcUrl, USERNAME, PASSWORD, null);
      return new TestDatabase(db, dataSource);
    } catch (final IOException e) {
      throw new UncheckedIOException("Unable to create embedded postgres database", e);
    }
  }

  public static final class TestDatabase implements Closeable {
    private final EmbeddedPostgres db;
    private final DataSource dataSource;

    private TestDatabase(final EmbeddedPostgres db, final DataSource dataSource) {
      this.db = db;
      this.dataSource = dataSource;
    }

    public DataSource getDataSource() {
      return dataSource;
    }

    @Override
    public void close() throws IOException {
      db.close();
    }
  }
}
