/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.keystorage.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustStoreLoaderTest {
  private static final String PASSWORD = "password";

  @TempDir Path tempDir;

  @Test
  void pkcs12TrustStoreTrustsOnlyItsCertificates() throws Exception {
    final SelfSignedCertificate cert = SelfSignedCertificate.generate();
    final Path trustStore = CertificateHelpers.createPkcs12TrustStore(tempDir, cert, PASSWORD);

    assertThat(acceptedIssuers(trustStore, Optional.of(PASSWORD)))
        .containsExactly(cert.getCertificate());
  }

  @Test
  void jksTrustStoreIsDetected() throws Exception {
    final SelfSignedCertificate cert = SelfSignedCertificate.generate();
    final Path trustStore = CertificateHelpers.createJksTrustStore(tempDir, cert, PASSWORD);

    assertThat(acceptedIssuers(trustStore, Optional.of(PASSWORD)))
        .containsExactly(cert.getCertificate());
  }

  @Test
  void pemBundleIsDetectedAndOtherContentIgnored() throws Exception {
    final SelfSignedCertificate first = SelfSignedCertificate.generate();
    final SelfSignedCertificate second = SelfSignedCertificate.generate();
    // as produced by "openssl pkcs12 -nokeys" or a combined key and certificate file
    final Path trustStore = tempDir.resolve("bundle.pem");
    Files.writeString(
        trustStore,
        "Bag Attributes\n    friendlyName: first\nsubject=CN = localhost\n"
            + pem(first, "first")
            + pemPrivateKey(second)
            + pem(second, "second"));

    assertThat(TrustStoreLoader.isPem(trustStore)).isTrue();
    assertThat(acceptedIssuers(trustStore, Optional.empty()))
        .containsExactlyInAnyOrder(first.getCertificate(), second.getCertificate());
  }

  @Test
  void pemWithoutCertificatesIsRejected() throws Exception {
    final Path trustStore = tempDir.resolve("key.pem");
    Files.writeString(trustStore, pemPrivateKey(SelfSignedCertificate.generate()));

    assertThatThrownBy(() -> acceptedIssuers(trustStore, Optional.empty()))
        .isInstanceOf(KeyStoreException.class)
        .hasMessage("Truststore does not contain any trusted certificates");
  }

  @Test
  void keyStoreWithoutPasswordIsRejected() {
    final Path trustStore =
        CertificateHelpers.createPkcs12TrustStore(
            tempDir, SelfSignedCertificate.generate(), PASSWORD);

    assertThatThrownBy(() -> acceptedIssuers(trustStore, Optional.empty()))
        .isInstanceOf(KeyStoreException.class)
        .hasMessage("A password is required for PKCS#12 and JKS truststores");
  }

  @Test
  void keyStoreWithWrongPasswordIsRejected() {
    final Path trustStore =
        CertificateHelpers.createPkcs12TrustStore(
            tempDir, SelfSignedCertificate.generate(), PASSWORD);

    assertThatThrownBy(() -> acceptedIssuers(trustStore, Optional.of("wrong")))
        .isInstanceOf(IOException.class);
  }

  @Test
  void keyStoreWithoutCertificatesIsRejected() throws Exception {
    final Path trustStore = tempDir.resolve("empty.p12");
    final KeyStore empty = KeyStore.getInstance("PKCS12");
    empty.load(null, null);
    try (final OutputStream out = Files.newOutputStream(trustStore)) {
      empty.store(out, PASSWORD.toCharArray());
    }

    assertThat(TrustStoreLoader.isPem(trustStore)).isFalse();
    assertThatThrownBy(() -> acceptedIssuers(trustStore, Optional.of(PASSWORD)))
        .isInstanceOf(KeyStoreException.class)
        .hasMessage("Truststore does not contain any trusted certificates");
  }

  private static X509Certificate[] acceptedIssuers(
      final Path trustStore, final Optional<String> password) throws Exception {
    return ((X509TrustManager)
            TrustStoreLoader.createTrustManagerFactory(trustStore, password).getTrustManagers()[0])
        .getAcceptedIssuers();
  }

  private String pem(final SelfSignedCertificate cert, final String name) throws Exception {
    final Path file = tempDir.resolve(name + ".crt");
    cert.writeCertificateToFile(file);
    return Files.readString(file);
  }

  private String pemPrivateKey(final SelfSignedCertificate cert) throws IOException {
    final Path file = tempDir.resolve("private.key");
    cert.writePrivateKeyToFile(file);
    return Files.readString(file);
  }
}
