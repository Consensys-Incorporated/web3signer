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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.Period;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class SelfSignedCertificate {

  private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
  private static final boolean IS_CA = true;
  private static final String distinguishedName = "CN=localhost";
  private static final List<String> sanHostNames = List.of("localhost");
  private static final List<String> sanIpAddresses = List.of("127.0.0.1");

  private final KeyPair keyPair; // not sure if this is needed.
  private final X509Certificate certificate;

  public SelfSignedCertificate(final KeyPair keyPair, final X509Certificate certificate) {
    this.keyPair = keyPair;
    this.certificate = certificate;
  }

  public static SelfSignedCertificate generate() {
    return generate(List.of());
  }

  public static SelfSignedCertificate generate(final List<String> additionalSanHostNames) {
    try {
      final KeyPair keyPair = generateKeyPair();
      return new SelfSignedCertificate(
          keyPair, generateSelfSignedCertificate(keyPair, additionalSanHostNames));
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static KeyPair generateKeyPair() throws GeneralSecurityException {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048, new SecureRandom());
    return keyPairGenerator.generateKeyPair();
  }

  private static X509Certificate generateSelfSignedCertificate(
      final KeyPair keyPair, final List<String> additionalSanHostNames)
      throws CertIOException, GeneralSecurityException, OperatorCreationException {
    final X500Name issuer = new X500Name(distinguishedName);
    final X500Name subject = new X500Name(distinguishedName);
    final BigInteger serialNumber = new BigInteger(String.valueOf(Instant.now().toEpochMilli()));
    final X509v3CertificateBuilder v3CertificateBuilder =
        new JcaX509v3CertificateBuilder(
            issuer,
            serialNumber,
            Date.from(Instant.now()),
            Date.from(Instant.now().plus(Period.ofDays(90))),
            subject,
            keyPair.getPublic());

    // extensions
    v3CertificateBuilder.addExtension(
        Extension.basicConstraints, true, new BasicConstraints(IS_CA));
    v3CertificateBuilder.addExtension(
        Extension.subjectAlternativeName,
        false,
        getSubjectAlternativeNames(additionalSanHostNames));

    final ContentSigner contentSigner =
        new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

    return new JcaX509CertificateConverter()
        .setProvider(BOUNCY_CASTLE_PROVIDER)
        .getCertificate(v3CertificateBuilder.build(contentSigner));
  }

  private static GeneralNames getSubjectAlternativeNames(
      final List<String> additionalSanHostNames) {
    final List<GeneralName> hostGeneralNames =
        Stream.concat(sanHostNames.stream(), additionalSanHostNames.stream())
            .distinct()
            .map(hostName -> new GeneralName(GeneralName.dNSName, hostName))
            .collect(Collectors.toList());
    final List<GeneralName> ipGeneralNames =
        sanIpAddresses.stream()
            .map(ipAddress -> new GeneralName(GeneralName.iPAddress, ipAddress))
            .collect(Collectors.toList());
    final GeneralName[] generalNames =
        Stream.of(hostGeneralNames, ipGeneralNames)
            .flatMap(Collection::stream)
            .toArray(GeneralName[]::new);

    return new GeneralNames(generalNames);
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

  public void writePrivateKeyToFile(final Path outputFile) throws IOException {
    try (final BufferedWriter writer = Files.newBufferedWriter(outputFile, UTF_8);
        final PemWriter pemWriter = new PemWriter(writer)) {
      pemWriter.writeObject(new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
    }
  }

  public void writeCertificateToFile(final Path pemFile)
      throws IOException, CertificateEncodingException {
    try (final BufferedWriter writer = Files.newBufferedWriter(pemFile, UTF_8);
        final PemWriter pemWriter = new PemWriter(writer)) {
      pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
    }
  }
}
