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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.common.config.AwsCredentials;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.keystorage.postgres.DecryptedBlsKey;
import tech.pegasys.web3signer.keystorage.postgres.PostgresBulkKeyLoader;
import tech.pegasys.web3signer.keystorage.postgres.PostgresConnectionFactory;
import tech.pegasys.web3signer.keystorage.postgres.PostgresKeystoreVersionChecker;
import tech.pegasys.web3signer.keystorage.postgres.kek.KekResolver;
import tech.pegasys.web3signer.keystorage.postgres.kek.awskms.AwsKmsKekCredentials;
import tech.pegasys.web3signer.keystorage.postgres.kek.awskms.PostgresAwsKmsKekResolver;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.config.PostgresAwsKmsKekParameters;
import tech.pegasys.web3signer.signing.config.PostgresKeystoreParameters;
import tech.pegasys.web3signer.signing.config.metadata.SignerOrigin;

import java.io.Closeable;
import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.sql.DataSource;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Bulk-loads BLS signing keys from the postgres keystore. Unlike the other {@code Bls*BulkLoader}
 * classes, this one is long-lived by design: it must be constructed once (holding a connection pool
 * and a DEK cache) and reused across startup and every {@code /reload} so the DEK cache actually
 * has a chance to serve cache hits across reload cycles - see {@link PostgresBulkKeyLoader}.
 */
public class BlsPostgresBulkLoader implements Closeable {

  private static final Logger LOG = LogManager.getLogger();

  private final DataSource dataSource;
  private final PostgresAwsKmsKekResolver awsKmsKekResolver;
  private final PostgresBulkKeyLoader postgresBulkKeyLoader;

  public BlsPostgresBulkLoader(
      final PostgresKeystoreParameters postgresKeystoreParameters,
      final PostgresAwsKmsKekParameters awsKmsKekParameters) {
    this.dataSource =
        PostgresConnectionFactory.createDataSource(
            postgresKeystoreParameters.getDbUrl(),
            postgresKeystoreParameters.getDbUsername(),
            postgresKeystoreParameters.getDbPassword(),
            postgresKeystoreParameters.getDbPoolConfigurationFile());
    PostgresKeystoreVersionChecker.verifyVersion(dataSource);

    this.awsKmsKekResolver =
        new PostgresAwsKmsKekResolver(toAwsKmsKekCredentials(awsKmsKekParameters));
    final Map<String, KekResolver> resolversByVaultType =
        Map.of(awsKmsKekResolver.vaultType(), awsKmsKekResolver);

    this.postgresBulkKeyLoader =
        new PostgresBulkKeyLoader(
            dataSource,
            resolversByVaultType,
            postgresKeystoreParameters.getDekCacheTtl(),
            postgresKeystoreParameters.getDecryptionParallelism());
  }

  public MappedResults<ArtifactSigner> load() {
    final MappedResults<DecryptedBlsKey> decrypted = postgresBulkKeyLoader.loadAll();
    final Set<ArtifactSigner> signers = new HashSet<>();
    int mappingErrors = 0;
    for (final DecryptedBlsKey key : decrypted.getValues()) {
      final ArtifactSigner signer = toArtifactSigner(key);
      if (signer != null) {
        signers.add(signer);
      } else {
        mappingErrors++;
      }
    }
    return MappedResults.newInstance(signers, decrypted.getErrorCount() + mappingErrors);
  }

  /** The number of KEK vault calls made during the most recent {@link #load()} invocation. */
  public int getLastVaultCallCount() {
    return postgresBulkKeyLoader.getLastVaultCallCount();
  }

  private static ArtifactSigner toArtifactSigner(final DecryptedBlsKey key) {
    try {
      final BLSKeyPair keyPair =
          new BLSKeyPair(BLSSecretKey.fromBytes(Bytes32.wrap(key.rawSecretKeyBytes())));
      return new BlsArtifactSigner(keyPair, SignerOrigin.POSTGRES);
    } catch (final Exception e) {
      LOG.warn(
          "Failed to construct BLS key pair for '{}', discarding: {}",
          key.keyIdentifier(),
          e.getClass().getSimpleName());
      return null;
    }
  }

  private static AwsKmsKekCredentials toAwsKmsKekCredentials(
      final PostgresAwsKmsKekParameters parameters) {
    return new AwsKmsKekCredentials() {
      @Override
      public AwsAuthenticationMode getAuthenticationMode() {
        return parameters.getAuthenticationMode();
      }

      @Override
      public Optional<AwsCredentials> getCredentials() {
        if (parameters.getAccessKeyId() == null || parameters.getSecretAccessKey() == null) {
          return Optional.empty();
        }
        return Optional.of(
            AwsCredentials.builder()
                .withAccessKeyId(parameters.getAccessKeyId())
                .withSecretAccessKey(parameters.getSecretAccessKey())
                .build());
      }

      @Override
      public Optional<URI> getEndpointOverride() {
        return parameters.getEndpointOverride();
      }
    };
  }

  @Override
  public void close() {
    // postgresBulkKeyLoader also closes the datasource, since it created it via
    // PostgresConnectionFactory and owns its lifecycle.
    postgresBulkKeyLoader.close();
    awsKmsKekResolver.close();
  }
}
