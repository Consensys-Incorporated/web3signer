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
package tech.pegasys.web3signer.signing.secp256k1.azure;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import tech.pegasys.web3signer.signing.secp256k1.Signature;

import java.math.BigInteger;
import java.security.SignatureException;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

public class AzureKeyVaultSignerTest {
  private static final ECKeyPair KEY_PAIR = ECKeyPair.create(BigInteger.ONE);

  @Test
  void reusesCryptographyClientAcrossSignatures() throws SignatureException {
    final CryptographyClient cryptoClient = mock(CryptographyClient.class);
    final SignResult signResult = mock(SignResult.class);
    final byte[] data = "Hello World".getBytes(UTF_8);
    final byte[] digest = Hash.sha3(data);
    final SignatureData remoteSignature = Sign.signMessage(digest, KEY_PAIR, false);
    final byte[] p1363Signature =
        Bytes.concatenate(Bytes.wrap(remoteSignature.getR()), Bytes.wrap(remoteSignature.getS()))
            .toArray();
    when(signResult.getSignature()).thenReturn(p1363Signature);
    when(cryptoClient.sign(eq(SignatureAlgorithm.ES256K), aryEq(digest))).thenReturn(signResult);
    final AzureKeyVaultSigner signer =
        new AzureKeyVaultSigner(
            Bytes.wrap(Numeric.toBytesPadded(KEY_PAIR.getPublicKey(), 64)),
            true,
            false,
            cryptoClient);

    final Signature firstSignature = signer.sign(data);
    final Signature secondSignature = signer.sign(data);

    assertThat(recoverPublicKey(data, firstSignature)).isEqualTo(KEY_PAIR.getPublicKey());
    assertThat(recoverPublicKey(data, secondSignature)).isEqualTo(KEY_PAIR.getPublicKey());
    verify(cryptoClient, times(2)).sign(eq(SignatureAlgorithm.ES256K), aryEq(digest));
  }

  private static BigInteger recoverPublicKey(final byte[] data, final Signature signature)
      throws SignatureException {
    final SignatureData signatureData =
        new SignatureData(
            signature.getV().toByteArray(),
            Numeric.toBytesPadded(signature.getR(), 32),
            Numeric.toBytesPadded(signature.getS(), 32));
    return Sign.signedMessageToKey(data, signatureData);
  }
}
