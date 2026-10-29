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

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Loads a truststore, detecting its format from the file content: PEM certificates, PKCS#12 or JKS.
 */
public final class TrustStoreLoader {
  private static final Pattern PEM_CERTIFICATE =
      Pattern.compile("-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", Pattern.DOTALL);

  private TrustStoreLoader() {}

  /**
   * Returns true if the file contains PEM encoded certificates rather than a PKCS#12 or JKS
   * keystore.
   */
  public static boolean isPem(final Path trustStoreFile) throws IOException {
    return isPem(Files.readAllBytes(trustStoreFile));
  }

  /**
   * Creates a {@link TrustManagerFactory} trusting only the certificates in the given truststore.
   *
   * <p>PEM files may contain several certificates and other text, such as {@code openssl} "Bag
   * Attributes" or private keys, which is ignored. PKCS#12 and JKS truststores require a password.
   *
   * @param trustStoreFile PEM, PKCS#12 or JKS file
   * @param password truststore password; not used for PEM files
   * @return trust manager factory to validate peer certificates with
   * @throws KeyStoreException if the truststore contains no trusted certificates or a password is
   *     required but missing
   */
  public static TrustManagerFactory createTrustManagerFactory(
      final Path trustStoreFile, final Optional<String> password)
      throws IOException, GeneralSecurityException {
    final byte[] content = Files.readAllBytes(trustStoreFile);
    final KeyStore trustStore =
        isPem(content) ? loadPem(content) : loadKeyStore(trustStoreFile, password);

    final TrustManagerFactory factory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    factory.init(trustStore);
    // e.g. "openssl pkcs12 -nokeys" output without Java trust attributes loads as an empty store
    if (x509TrustManager(factory).getAcceptedIssuers().length == 0) {
      throw new KeyStoreException("Truststore does not contain any trusted certificates");
    }
    return factory;
  }

  private static boolean isPem(final byte[] content) {
    return new String(content, US_ASCII).contains("-----BEGIN ");
  }

  private static KeyStore loadPem(final byte[] content)
      throws IOException, GeneralSecurityException {
    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);

    final Matcher matcher = PEM_CERTIFICATE.matcher(new String(content, US_ASCII));
    int index = 0;
    while (matcher.find()) {
      final Certificate certificate =
          certificateFactory.generateCertificate(
              new ByteArrayInputStream(matcher.group().getBytes(US_ASCII)));
      trustStore.setCertificateEntry("pem-" + index++, certificate);
    }
    return trustStore;
  }

  private static KeyStore loadKeyStore(final Path trustStoreFile, final Optional<String> password)
      throws IOException, GeneralSecurityException {
    if (password.isEmpty()) {
      throw new KeyStoreException("A password is required for PKCS#12 and JKS truststores");
    }
    // detects PKCS#12 or JKS
    return KeyStore.getInstance(trustStoreFile.toFile(), password.get().toCharArray());
  }

  private static X509TrustManager x509TrustManager(final TrustManagerFactory factory) {
    for (final TrustManager trustManager : factory.getTrustManagers()) {
      if (trustManager instanceof X509TrustManager x509TrustManager) {
        return x509TrustManager;
      }
    }
    throw new IllegalStateException("No X509TrustManager available");
  }
}
