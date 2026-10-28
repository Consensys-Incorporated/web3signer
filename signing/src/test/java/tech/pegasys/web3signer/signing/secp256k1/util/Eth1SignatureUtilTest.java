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
package tech.pegasys.web3signer.signing.secp256k1.util;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.signing.secp256k1.EthPublicKeyUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

public class Eth1SignatureUtilTest {
  public static final byte[] DATA_TO_SIGN = Hash.sha3("hello".getBytes(StandardCharsets.UTF_8));

  @Test
  void signatureIsDerivedFromDerEncoded() throws Exception {
    final KeyPair keyPair = EthPublicKeyUtils.generateK256KeyPair();
    final ECKeyPair web3jECKeyPair = ECKeyPair.create(keyPair);

    // sign using web3j (which uses BouncyCastle ECDSA Signer)
    final ECDSASignature web3jSig = web3jECKeyPair.sign(DATA_TO_SIGN);

    // convert web3j's P1363 to ANS1/DER Encoded signature
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(web3jSig.r));
    v.add(new ASN1Integer(web3jSig.s));
    final byte[] derEncodedSignedData = new DERSequence(v).getEncoded();

    // verify our logic
    final tech.pegasys.web3signer.signing.secp256k1.Signature signature =
        Eth1SignatureUtil.deriveSignatureFromDerEncoded(
            DATA_TO_SIGN, (ECPublicKey) keyPair.getPublic(), derEncodedSignedData);

    assertThat(signature.getR()).isEqualTo(web3jSig.r);
    assertThat(signature.getS()).isEqualTo(web3jSig.s);
  }

  @Test
  void signatureIsDerivedFromP1363Encoded() throws Exception {
    final KeyPair keyPair = EthPublicKeyUtils.generateK256KeyPair();
    final ECKeyPair web3jECKeyPair = ECKeyPair.create(keyPair);
    // sign using web3j (which uses BouncyCastle ECDSASigner)
    final ECDSASignature web3jSig = web3jECKeyPair.sign(DATA_TO_SIGN);

    // verify our logic
    final tech.pegasys.web3signer.signing.secp256k1.Signature signature =
        Eth1SignatureUtil.deriveSignatureFromP1363Encoded(
            DATA_TO_SIGN, (ECPublicKey) keyPair.getPublic(), toP1363(web3jSig));

    assertThat(signature.getR()).isEqualTo(web3jSig.r);
    assertThat(signature.getS()).isEqualTo(web3jSig.s);
  }

  // RFC 6979 signing is deterministic: with these private keys, r (699) or s (105) of the signature
  // over DATA_TO_SIGN is below 2^248, so its fixed-width P1363 encoding starts with a zero byte.
  @ParameterizedTest
  @ValueSource(longs = {699, 105})
  void signatureIsDerivedFromP1363EncodedWithLeadingZeroComponent(final long privateKey) {
    final ECKeyPair web3jECKeyPair = ECKeyPair.create(BigInteger.valueOf(privateKey));
    final ECDSASignature web3jSig = web3jECKeyPair.sign(DATA_TO_SIGN);
    assertThat(web3jSig.r.min(web3jSig.s).bitLength()).isLessThanOrEqualTo(248);

    final tech.pegasys.web3signer.signing.secp256k1.Signature signature =
        Eth1SignatureUtil.deriveSignatureFromP1363Encoded(
            DATA_TO_SIGN,
            EthPublicKeyUtils.web3JPublicKeyToECPublicKey(web3jECKeyPair.getPublicKey()),
            toP1363(web3jSig));

    assertThat(signature.getR()).isEqualTo(web3jSig.r);
    assertThat(signature.getS()).isEqualTo(web3jSig.s);
  }

  // P1363 is r || s, each left-padded to the 32-byte curve order size
  private static byte[] toP1363(final ECDSASignature signature) {
    final byte[] p1363 = new byte[64];
    System.arraycopy(Numeric.toBytesPadded(signature.r, 32), 0, p1363, 0, 32);
    System.arraycopy(Numeric.toBytesPadded(signature.s, 32), 0, p1363, 32, 32);
    return p1363;
  }
}
