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
package tech.pegasys.web3signer.keystorage.hashicorp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;
import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Optional;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustManagerFactoryProviderTest {
  private static final String PASSWORD = "password";

  @TempDir Path tempDir;

  @Test
  void jksFileTaggedAsPkcs12IsLoaded() throws Exception {
    final SelfSignedCertificate cert = SelfSignedCertificate.generate();
    final Path jks = CertificateHelpers.createJksTrustStore(tempDir, cert, PASSWORD);

    final X509TrustManager trustManager =
        (X509TrustManager)
            TrustManagerFactoryProvider.getTrustManagerFactory(
                    new TlsOptions(Optional.of(TrustStoreType.PKCS12), jks, PASSWORD))
                .getTrustManagers()[0];

    assertThat(trustManager.getAcceptedIssuers()).containsExactly(cert.getCertificate());
  }

  @Test
  void pkcs12WithoutCertificatesIsRejected() throws Exception {
    final Path trustStore = tempDir.resolve("empty.p12");
    final KeyStore empty = KeyStore.getInstance("PKCS12");
    empty.load(null, null);
    try (final OutputStream out = Files.newOutputStream(trustStore)) {
      empty.store(out, PASSWORD.toCharArray());
    }

    assertThatThrownBy(
            () ->
                TrustManagerFactoryProvider.getTrustManagerFactory(
                    new TlsOptions(Optional.of(TrustStoreType.PKCS12), trustStore, PASSWORD)))
        .isInstanceOf(KeyStoreException.class)
        .hasMessage("Truststore does not contain any trusted certificates");
  }
}
