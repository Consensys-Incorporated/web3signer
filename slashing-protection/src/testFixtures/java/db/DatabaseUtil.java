/*
 * Copyright 2022 ConsenSys AG.
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
package db;

import tech.pegasys.web3signer.slashingprotection.DbConnection;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.jdbi.v3.core.Jdbi;

/**
 * Test databases on one embedded Postgres cluster per JVM. The cluster's {@code template1} is
 * migrated once, and every {@link #create()} clones it into a new database, so tests stay isolated
 * while {@code initdb} and the postmaster start run once per test fork rather than once per test.
 */
public final class DatabaseUtil {
  public static final String USERNAME = "postgres";
  public static final String PASSWORD = "postgres";
  public static final String MIGRATIONS_LOCATION = "/migrations/postgresql/";

  /**
   * A Hikari pool per test would hold its idle connections open on the shared cluster until {@code
   * max_connections} is exhausted; unpooled connections close with their Jdbi handle.
   */
  public static final boolean DB_CONNECTION_POOL_ENABLED = false;

  /** A cold start under a busy test run can exceed zonky's default of 10 seconds. */
  private static final Duration STARTUP_WAIT = Duration.ofMinutes(2);

  private static final AtomicInteger DATABASE_COUNTER = new AtomicInteger();

  // guarded by DatabaseUtil.class
  private static EmbeddedPostgres cluster;

  private DatabaseUtil() {}

  /** A new database with all migrations applied. */
  public static TestDatabaseInfo create() {
    return createFrom("template1");
  }

  /** A new empty database, for tests that run the migrations themselves. */
  public static TestDatabaseInfo createWithoutMigration() {
    return createFrom("template0");
  }

  private static TestDatabaseInfo createFrom(final String template) {
    final EmbeddedPostgres pg = cluster();
    final String name = "test_" + DATABASE_COUNTER.incrementAndGet();
    try (Connection connection = pg.getPostgresDatabase().getConnection();
        Statement statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + name + " TEMPLATE " + template);
    } catch (final SQLException e) {
      throw new IllegalStateException("Unable to create test database " + name, e);
    }
    final String url = String.format("jdbc:postgresql://localhost:%d/%s", pg.getPort(), name);
    return new TestDatabaseInfo(
        url,
        pg.getDatabase(USERNAME, name),
        DbConnection.createConnection(url, USERNAME, PASSWORD, null, DB_CONNECTION_POOL_ENABLED));
  }

  /**
   * Started on first use rather than in a static initializer, so a failed start fails only the
   * calling test instead of every later test of the JVM. A cluster whose migration fails is closed
   * before rethrowing, so its postmaster does not outlive the failure.
   */
  private static synchronized EmbeddedPostgres cluster() {
    if (cluster == null) {
      final EmbeddedPostgres pg;
      try {
        pg = EmbeddedPostgres.builder().setPGStartupWait(STARTUP_WAIT).start();
      } catch (final IOException e) {
        throw new UncheckedIOException("Unable to start embedded postgres", e);
      }
      try {
        Flyway.configure()
            .locations(MIGRATIONS_LOCATION)
            .dataSource(pg.getTemplateDatabase())
            .load()
            .migrate();
      } catch (final RuntimeException e) {
        try {
          pg.close();
        } catch (final IOException closeFailure) {
          e.addSuppressed(closeFailure);
        }
        throw e;
      }
      cluster = pg;
    }
    return cluster;
  }

  public record TestDatabaseInfo(String databaseUrl, DataSource dataSource, Jdbi jdbi) {}
}
