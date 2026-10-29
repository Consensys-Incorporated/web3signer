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
package tech.pegasys.web3signer.signing.config.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.web3signer.BLSTestUtil;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.model.CipherFunction;
import tech.pegasys.web3signer.bls.keystore.model.CipherParam;
import tech.pegasys.web3signer.bls.keystore.model.CipherSpec;
import tech.pegasys.web3signer.bls.keystore.model.KdfParam;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.bls.keystore.model.SCryptParam;
import tech.pegasys.web3signer.keystorage.aws.AwsSecretsManagerProvider;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnection;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.web3signer.keystorage.hashicorp.TrustStoreType;
import tech.pegasys.web3signer.keystorage.hashicorp.VaultAuthMethod;
import tech.pegasys.web3signer.keystorage.hashicorp.config.ConnectionParameters;
import tech.pegasys.web3signer.keystorage.hashicorp.config.KubernetesAuthOptions;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import io.vertx.core.Vertx;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes48;
import org.hyperledger.besu.metrics.noop.NoOpMetricsSystem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BlsArtifactSignerFactoryTest {
  private static final String PASSWORD = "testpassword";
  private static final Bytes KEYSTORE_SALT =
      Bytes.fromHexString("1f2b6d2bac495b05ec65f49e8d9def356b29b65a0b80260a884d6d393073ff7b");
  private static final String KEYSTORE_FILE_NAME = "keystore.json";
  private static final String PASSWORD_FILE_NAME = "keystore.password";
  private static final BLSKeyPair BLS_KEY_PAIR = BLSTestUtil.randomKeyPair(48);

  @TempDir static Path configDir;
  private static Path keystoreFile;
  private static Path passwordFile;
  private ArtifactSignerFactory artifactSignerFactory;

  private Vertx vertx;
  private AwsSecretsManagerProvider awsSecretsManagerProvider;
  private AzureKeyVaultFactory azureKeyVaultFactory;

  @BeforeAll
  static void setupKeystoreFiles() throws IOException {
    keystoreFile = configDir.resolve(KEYSTORE_FILE_NAME);
    passwordFile = configDir.resolve(PASSWORD_FILE_NAME);

    createKeyStoreFile(keystoreFile);
    Files.writeString(passwordFile, "testpassword");
  }

  @BeforeEach
  void setup() {
    vertx = Vertx.vertx();
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(100);
    azureKeyVaultFactory = new AzureKeyVaultFactory();

    artifactSignerFactory =
        new BlsArtifactSignerFactory(
            configDir,
            new NoOpMetricsSystem(),
            new HashicorpConnectionFactory(),
            awsSecretsManagerProvider,
            (args) -> new BlsArtifactSigner(args.getKeyPair(), args.getOrigin()),
            azureKeyVaultFactory);
  }

  @AfterEach
  void cleanup() {
    vertx.close();
  }

  @Test
  void createsArtifactSignerFromKeyStoreUsingRelativePaths() {
    final Path relativeKeystorePath = Path.of(KEYSTORE_FILE_NAME);
    final Path relativePasswordPath = Path.of(PASSWORD_FILE_NAME);
    final ArtifactSigner artifactSigner =
        artifactSignerFactory.create(
            new FileKeyStoreMetadata(relativeKeystorePath, relativePasswordPath, KeyType.BLS));

    assertThat(relativeKeystorePath).isRelative();
    assertThat(relativePasswordPath).isRelative();
    assertThat(artifactSigner.getIdentifier()).startsWith("0x");
    assertThat(fromIdentifier(artifactSigner.getIdentifier()))
        .isEqualTo(BLS_KEY_PAIR.getPublicKey());
  }

  @Test
  void createsArtifactSignerFromKeyStoreUsingAbsolutePaths() {
    final ArtifactSigner artifactSigner =
        artifactSignerFactory.create(
            new FileKeyStoreMetadata(keystoreFile, passwordFile, KeyType.BLS));

    assertThat(keystoreFile).isAbsolute();
    assertThat(passwordFile).isAbsolute();
    assertThat(artifactSigner.getIdentifier()).startsWith("0x");
    assertThat(fromIdentifier(artifactSigner.getIdentifier()))
        .isEqualTo(BLS_KEY_PAIR.getPublicKey());
  }

  private BLSPublicKey fromIdentifier(final String identifier) {
    return BLSPublicKey.fromBytesCompressedValidate(Bytes48.wrap(Bytes.fromHexString(identifier)));
  }

  @Test
  void nonExistentKeyStoreThrowsError() {
    final Path nonExistingKeystoreFile = configDir.resolve("someNonExistingKeystore");
    final FileKeyStoreMetadata fileKeyStoreMetadata =
        new FileKeyStoreMetadata(nonExistingKeystoreFile, passwordFile, KeyType.BLS);

    assertThatThrownBy(() -> artifactSignerFactory.create(fileKeyStoreMetadata))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessageStartingWith("Failed to read keystore file:")
        .hasMessageContaining(nonExistingKeystoreFile.toString());
  }

  @Test
  void invalidKeystorePasswordThrowsError() throws IOException {
    final Path invalidPasswordFile = configDir.resolve("invalidPassword");
    Files.writeString(invalidPasswordFile, "invalid_password");

    final FileKeyStoreMetadata fileKeyStoreMetadata =
        new FileKeyStoreMetadata(keystoreFile, invalidPasswordFile, KeyType.BLS);

    assertThatThrownBy(() -> artifactSignerFactory.create(fileKeyStoreMetadata))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("Failed to decrypt KeyStore, checksum validation failed.");
  }

  @Test
  void emptyKeystorePasswordThrowsError() throws IOException {
    final Path emptyPasswordFile = configDir.resolve("emptyPassword");
    Files.createFile(emptyPasswordFile);

    final FileKeyStoreMetadata fileKeyStoreMetadata =
        new FileKeyStoreMetadata(keystoreFile, emptyPasswordFile, KeyType.BLS);

    assertThatThrownBy(() -> artifactSignerFactory.create(fileKeyStoreMetadata))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("Keystore password cannot be empty: " + emptyPasswordFile);
  }

  @Test
  void nonExistentKeystorePasswordThrowsError() {
    final Path nonExistentPassword = configDir.resolve("nonExistentPassword");

    final FileKeyStoreMetadata fileKeyStoreMetadata =
        new FileKeyStoreMetadata(keystoreFile, nonExistentPassword, KeyType.BLS);

    assertThatThrownBy(() -> artifactSignerFactory.create(fileKeyStoreMetadata))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("Keystore password file not found: " + nonExistentPassword);
  }

  @Test
  @SuppressWarnings("removal") // deprecated tlsKnownServersPath
  void malformedKnownServersFileShowsSuitableError() throws IOException {

    final Path malformedknownServers = configDir.resolve("malformedKnownServers");
    Files.writeString(malformedknownServers, "Illegal Known Servers.");

    final HashicorpSigningMetadata metaData =
        new HashicorpSigningMetadata("localhost", "keyPath", KeyType.BLS);
    metaData.setToken("token");
    metaData.setTlsEnabled(true);
    metaData.setTlsKnownServersPath(malformedknownServers);

    assertThatThrownBy(() -> artifactSignerFactory.create(metaData))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("Unable to initialise connection to hashicorp vault.");
  }

  @Test
  void relativePkcs12TruststorePathsAreResolvedAgainstConfigDirectory() throws IOException {
    Files.write(configDir.resolve("truststore.p12"), new byte[] {0x30, (byte) 0x82});
    Files.writeString(configDir.resolve("truststore.pass"), "trustPassword");
    final HashicorpSigningMetadata metaData = tlsMetadata(Path.of("truststore.p12"));
    metaData.setTlsTruststorePasswordFile(Path.of("truststore.pass"));

    final TlsOptions tlsOptions = captureTlsOptions(metaData);

    assertThat(tlsOptions.getTrustStoreType()).contains(TrustStoreType.PKCS12);
    assertThat(tlsOptions.getTrustStorePath()).isEqualTo(configDir.resolve("truststore.p12"));
    assertThat(tlsOptions.getTrustStorePassword()).isEqualTo("trustPassword");
  }

  @Test
  void pemTruststoreIsDetectedAndNeedsNoPassword() throws IOException {
    Files.writeString(
        configDir.resolve("truststore.pem"),
        "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
    final HashicorpSigningMetadata metaData = tlsMetadata(Path.of("truststore.pem"));

    final TlsOptions tlsOptions = captureTlsOptions(metaData);

    assertThat(tlsOptions.getTrustStoreType()).contains(TrustStoreType.PEM);
    assertThat(tlsOptions.getTrustStorePath()).isEqualTo(configDir.resolve("truststore.pem"));
    assertThat(tlsOptions.getTrustStorePassword()).isNull();
  }

  @Test
  void pkcs12TruststoreWithoutPasswordFileShowsSuitableError() throws IOException {
    Files.write(configDir.resolve("truststore.p12"), new byte[] {0x30, (byte) 0x82});
    final HashicorpSigningMetadata metaData = tlsMetadata(configDir.resolve("truststore.p12"));

    assertThatThrownBy(() -> artifactSignerFactory.create(metaData))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("tlsTruststorePasswordFile must be specified for a PKCS#12 or JKS truststore");
  }

  @Test
  void truststorePasswordFileWithoutTruststoreShowsSuitableError() {
    final HashicorpSigningMetadata metaData = tlsMetadata(null);
    metaData.setTlsTruststorePasswordFile(configDir.resolve("truststore.pass"));

    assertThatThrownBy(() -> artifactSignerFactory.create(metaData))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("tlsTruststorePasswordFile requires tlsTruststoreFile");
  }

  private static HashicorpSigningMetadata tlsMetadata(final Path trustStoreFile) {
    final HashicorpSigningMetadata metaData =
        new HashicorpSigningMetadata("localhost", "keyPath", KeyType.BLS);
    metaData.setToken("token");
    metaData.setTlsEnabled(true);
    metaData.setTlsTruststoreFile(trustStoreFile);
    return metaData;
  }

  private TlsOptions captureTlsOptions(final HashicorpSigningMetadata metaData) {
    final AtomicReference<TlsOptions> capturedTlsOptions = new AtomicReference<>();
    final HashicorpConnectionFactory connectionFactory =
        new HashicorpConnectionFactory() {
          @Override
          public HashicorpConnection create(final ConnectionParameters connectionParameters) {
            capturedTlsOptions.set(connectionParameters.getTlsOptions().orElseThrow());
            throw new SigningMetadataException("Connection intercepted");
          }
        };
    final ArtifactSignerFactory customFactory =
        new BlsArtifactSignerFactory(
            configDir,
            new NoOpMetricsSystem(),
            connectionFactory,
            awsSecretsManagerProvider,
            (args) -> new BlsArtifactSigner(args.getKeyPair(), args.getOrigin()),
            azureKeyVaultFactory);

    assertThatThrownBy(() -> customFactory.create(metaData)).hasMessage("Connection intercepted");
    return capturedTlsOptions.get();
  }

  @Test
  @SuppressWarnings("removal") // deprecated tlsKnownServersPath
  void truststoreWithKnownServersFileShowsSuitableError() {
    final HashicorpSigningMetadata metaData = tlsMetadata(configDir.resolve("truststore.p12"));
    metaData.setTlsTruststorePasswordFile(configDir.resolve("truststore.pass"));
    metaData.setTlsKnownServersPath(configDir.resolve("knownServers"));

    assertThatThrownBy(() -> artifactSignerFactory.create(metaData))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage(
            "tlsTruststoreFile cannot be specified together with the deprecated tlsKnownServersPath");
  }

  @Test
  void kubernetesAuthServiceAccountTokenPathIsResolvedToAbsolute() {
    final Path relativeTokenPath = Path.of("relative-token");
    final HashicorpSigningMetadata metaData =
        new HashicorpSigningMetadata("localhost", "keyPath", KeyType.BLS);
    metaData.setAuthMethod(VaultAuthMethod.KUBERNETES);
    metaData.setKubernetesRole("my-role");
    metaData.setKubernetesServiceAccountTokenPath(relativeTokenPath);

    final AtomicReference<KubernetesAuthOptions> capturedAuthOptions = new AtomicReference<>();

    final HashicorpConnection mockConnection = mock(HashicorpConnection.class);

    when(mockConnection.authenticateWithKubernetes(any()))
        .thenAnswer(
            invocation -> {
              final KubernetesAuthOptions kubernetesAuthOptions = invocation.getArgument(0);
              capturedAuthOptions.set(kubernetesAuthOptions);
              throw new SigningMetadataException("Authentication intercepted");
            });

    final HashicorpConnectionFactory connectionFactory =
        new HashicorpConnectionFactory() {
          @Override
          public HashicorpConnection create(final ConnectionParameters connectionParameters) {
            return mockConnection;
          }
        };

    final ArtifactSignerFactory customFactory =
        new BlsArtifactSignerFactory(
            configDir,
            new NoOpMetricsSystem(),
            connectionFactory,
            awsSecretsManagerProvider,
            (args) -> new BlsArtifactSigner(args.getKeyPair(), args.getOrigin()),
            azureKeyVaultFactory);

    assertThatThrownBy(() -> customFactory.create(metaData))
        .isInstanceOf(SigningMetadataException.class)
        .hasMessage("Authentication intercepted");

    assertThat(capturedAuthOptions.get()).isNotNull();
    assertThat(capturedAuthOptions.get().getServiceAccountTokenPath())
        .isEqualTo(configDir.resolve(relativeTokenPath));
  }

  private static void createKeyStoreFile(final Path keyStoreFilePath) {
    final KdfParam kdfParam = new SCryptParam(32, KEYSTORE_SALT);
    final CipherSpec cipher =
        new CipherSpec(
            CipherFunction.AES_128_CTR,
            new CipherParam(Bytes.fromHexString("e0f20a27d160f7cc92764579390e881a")));
    final KeyStoreData keyStoreData =
        KeyStore.encrypt(BLS_KEY_PAIR, PASSWORD, "", kdfParam, cipher);
    try {
      KeyStoreLoader.saveToFile(keyStoreFilePath, keyStoreData);
    } catch (IOException e) {
      fail("Unable to create keystore file", e);
    }
  }
}
