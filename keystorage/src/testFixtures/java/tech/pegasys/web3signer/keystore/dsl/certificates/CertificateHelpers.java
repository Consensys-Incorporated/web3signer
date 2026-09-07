/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.keystore.dsl.certificates;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Optional;

import org.apache.tuweni.net.tls.TLS;

public class CertificateHelpers {

  public static Path createFingerprintFile(
      final Path parentDir,
      final SelfSignedCertificate selfSignedCert,
      final Optional<Integer> port)
      throws IOException, CertificateEncodingException {

    final Path knownHostsPath = parentDir.resolve("knownhosts");
    final StringBuilder fingerPrintsToAdd = new StringBuilder();
    final String portFragment = port.map(p -> String.format(":%d", p)).orElse("");
    final String fingerprint = TLS.certificateHexFingerprint(selfSignedCert.getCertificate());
    fingerPrintsToAdd.append(String.format("localhost%s %s%n", portFragment, fingerprint));
    fingerPrintsToAdd.append(String.format("127.0.0.1%s %s%n", portFragment, fingerprint));
    Files.writeString(knownHostsPath, fingerPrintsToAdd.toString());

    return knownHostsPath;
  }

  public static Path createJksTrustStore(
      final Path parentDir, final SelfSignedCertificate selfSignedCert, final String password) {
    try {
      final Path keyStorePath = parentDir.resolve("keystore.jks");
      createTrustStore("JKS", selfSignedCert, password, keyStorePath);
      return keyStorePath;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to construct a JKS keystore.");
    }
  }

  public static Path createPkcs12TrustStore(
      final Path parentDir, final SelfSignedCertificate selfSignedCert, final String password) {
    try {
      final Path keyStorePath = parentDir.resolve("keystore.pfx");
      createTrustStore("pkcs12", selfSignedCert, password, keyStorePath);
      return keyStorePath;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to construct a PKCS12 keystore.");
    }
  }

  private static void createTrustStore(
      final String keystoreType,
      final SelfSignedCertificate selfSignedCert,
      final String password,
      final Path populatedFile)
      throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

    final KeyStore ks = KeyStore.getInstance(keystoreType);
    ks.load(null, null);

    final Certificate certificate = selfSignedCert.getCertificate();
    ks.setKeyEntry(
        "client",
        selfSignedCert.getKeyPair().getPrivate(),
        password.toCharArray(),
        new Certificate[] {certificate});

    try (final FileOutputStream output = new FileOutputStream(populatedFile.toFile())) {
      ks.store(output, password.toCharArray());
    }
  }
}
