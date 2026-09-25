/*
 * Copyright 2026 ConsenSys AG.
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

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.keystorage.postgres.crypto.AadCodec;
import tech.pegasys.web3signer.keystorage.postgres.crypto.AesGcmKeyCipher;
import tech.pegasys.web3signer.keystorage.postgres.kek.KekResolutionException;
import tech.pegasys.web3signer.keystorage.postgres.kek.KekResolver;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PostgresBulkKeyLoaderTest {

  private static final String VAULT_TYPE = "TEST";
  private static SecureRandom secureRandom = new SecureRandom();
  private PostgresKeystoreTestUtil.TestDatabase testDatabase;
  private DataSource dataSource;
  private final AesGcmKeyCipher cipher = new AesGcmKeyCipher();

  @BeforeEach
  void setUp() {
    testDatabase = PostgresKeystoreTestUtil.create();
    dataSource = testDatabase.getDataSource();
  }

  @AfterEach
  void tearDown() throws Exception {
    testDatabase.close();
  }

  @Test
  void decryptsAllKeysAndMakesExactlyOneVaultCallPerTenant() throws Exception {
    final byte[] dekA = randomKey();
    final byte[] dekB = randomKey();
    final int tenantAId = insertTenant("tenant-a", 1);
    final int tenantBId = insertTenant("tenant-b", 1);
    insertKey(tenantAId, "tenant-a", "key-a1", dekA, 1);
    insertKey(tenantAId, "tenant-a", "key-a2", dekA, 1);
    insertKey(tenantBId, "tenant-b", "key-b1", dekB, 1);

    final CountingFakeKekResolver resolver =
        new CountingFakeKekResolver(Map.of("tenant-a", dekA, "tenant-b", dekB));

    try (final PostgresBulkKeyLoader loader =
        new PostgresBulkKeyLoader(
            dataSource, Map.of(VAULT_TYPE, resolver), Duration.ofMinutes(15), 4)) {
      final var results = loader.loadAll();

      assertThat(results.getErrorCount()).isZero();
      assertThat(results.getValues())
          .extracting(DecryptedBlsKey::keyIdentifier)
          .containsExactlyInAnyOrder("key-a1", "key-a2", "key-b1");
      assertThat(resolver.resolveCount).hasValue(2); // exactly one call per tenant
      assertThat(loader.getLastVaultCallCount()).isEqualTo(2);
    }
  }

  @Test
  void secondLoadWithinTtlServesDekFromCacheWithNoAdditionalVaultCalls() throws Exception {
    final byte[] dek = randomKey();
    final int tenantId = insertTenant("tenant-a", 1);
    insertKey(tenantId, "tenant-a", "key-a1", dek, 1);

    final CountingFakeKekResolver resolver = new CountingFakeKekResolver(Map.of("tenant-a", dek));

    try (final PostgresBulkKeyLoader loader =
        new PostgresBulkKeyLoader(
            dataSource, Map.of(VAULT_TYPE, resolver), Duration.ofMinutes(15), 4)) {
      loader.loadAll();
      final var secondResult = loader.loadAll();

      assertThat(secondResult.getErrorCount()).isZero();
      assertThat(resolver.resolveCount).hasValue(1);
      assertThat(loader.getLastVaultCallCount()).isZero();
    }
  }

  @Test
  void rowEncryptedUnderStaleDekVersionIsSkippedAndCountedAsError() throws Exception {
    final byte[] dek = randomKey();
    final int tenantId = insertTenant("tenant-a", 2); // tenant's *current* version is 2
    insertKey(tenantId, "tenant-a", "stale-key", dek, 1); // but this row is still under version 1

    final CountingFakeKekResolver resolver = new CountingFakeKekResolver(Map.of("tenant-a", dek));

    try (final PostgresBulkKeyLoader loader =
        new PostgresBulkKeyLoader(
            dataSource, Map.of(VAULT_TYPE, resolver), Duration.ofMinutes(15), 4)) {
      final var results = loader.loadAll();

      assertThat(results.getValues()).isEmpty();
      assertThat(results.getErrorCount()).isEqualTo(1);
    }
  }

  @Test
  void tenantWithNoRegisteredResolverIsSkippedAndCountedAsError() throws Exception {
    final byte[] dek = randomKey();
    final int tenantId = insertTenant("tenant-a", 1);
    insertKey(tenantId, "tenant-a", "key-a1", dek, 1);

    try (final PostgresBulkKeyLoader loader =
        new PostgresBulkKeyLoader(dataSource, Map.of(), Duration.ofMinutes(15), 4)) {
      final var results = loader.loadAll();

      assertThat(results.getValues()).isEmpty();
      assertThat(results.getErrorCount()).isEqualTo(1);
    }
  }

  @Test
  void oneTenantFailingKekResolutionDoesNotPreventOtherTenantsFromLoading() throws Exception {
    final byte[] dekA = randomKey();
    final byte[] dekB = randomKey();
    final int tenantAId = insertTenant("tenant-a", 1);
    final int tenantBId = insertTenant("tenant-b", 1);
    insertKey(tenantAId, "tenant-a", "key-a1", dekA, 1);
    insertKey(tenantBId, "tenant-b", "key-b1", dekB, 1);

    // resolver only knows about tenant-b's DEK - tenant-a's resolution will fail
    final CountingFakeKekResolver resolver = new CountingFakeKekResolver(Map.of("tenant-b", dekB));

    try (final PostgresBulkKeyLoader loader =
        new PostgresBulkKeyLoader(
            dataSource, Map.of(VAULT_TYPE, resolver), Duration.ofMinutes(15), 4)) {
      final var results = loader.loadAll();

      assertThat(results.getValues())
          .extracting(DecryptedBlsKey::keyIdentifier)
          .containsExactly("key-b1");
      assertThat(results.getErrorCount()).isEqualTo(1);
    }
  }

  private int insertTenant(final String name, final int dekVersion) throws SQLException {
    try (final Connection connection = dataSource.getConnection();
        final PreparedStatement statement =
            connection.prepareStatement(
                "INSERT INTO tenants (name, vault_type, kek_key_id, encrypted_dek, dek_version)"
                    + " VALUES (?, ?, ?, ?, ?) RETURNING id")) {
      statement.setString(1, name);
      statement.setString(2, VAULT_TYPE);
      statement.setString(3, "test-kek-id");
      // content is irrelevant - CountingFakeKekResolver returns a fixed DEK without reading this
      statement.setBytes(4, new byte[] {0});
      statement.setInt(5, dekVersion);
      try (final var resultSet = statement.executeQuery()) {
        resultSet.next();
        return resultSet.getInt("id");
      }
    }
  }

  private void insertKey(
      final int tenantId,
      final String tenantName,
      final String keyIdentifier,
      final byte[] dek,
      final int dekVersion)
      throws SQLException, GeneralSecurityException {
    final byte[] aad = AadCodec.forRow(tenantName, keyIdentifier, dekVersion);
    final byte[] encryptedBlsKey = cipher.encrypt(dek, randomKey(), aad);
    try (final Connection connection = dataSource.getConnection();
        final PreparedStatement statement =
            connection.prepareStatement(
                "INSERT INTO bls_signing_keys (tenant_id, key_identifier, encrypted_bls_key,"
                    + " dek_version) VALUES (?, ?, ?, ?)")) {
      statement.setInt(1, tenantId);
      statement.setString(2, keyIdentifier);
      statement.setBytes(3, encryptedBlsKey);
      statement.setInt(4, dekVersion);
      statement.executeUpdate();
    }
  }

  private static byte[] randomKey() {
    final byte[] key = new byte[32];
    secureRandom.nextBytes(key);
    return key;
  }

  /** A fake {@link KekResolver} returning pre-known DEKs, for testing the loader in isolation. */
  private static final class CountingFakeKekResolver implements KekResolver {
    private final Map<String, byte[]> deksByTenantName;
    private final AtomicInteger resolveCount = new AtomicInteger();

    private CountingFakeKekResolver(final Map<String, byte[]> deksByTenantName) {
      this.deksByTenantName = deksByTenantName;
    }

    @Override
    public String vaultType() {
      return VAULT_TYPE;
    }

    @Override
    public byte[] unwrapDek(final TenantRecord tenant) {
      resolveCount.incrementAndGet();
      final byte[] dek = deksByTenantName.get(tenant.name());
      if (dek == null) {
        throw new KekResolutionException("No test DEK registered for tenant " + tenant.name());
      }
      return dek;
    }
  }
}
