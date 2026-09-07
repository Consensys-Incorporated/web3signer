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

import tech.pegasys.web3signer.signing.secp256k1.EthPublicKeyUtils;
import tech.pegasys.web3signer.signing.secp256k1.Signature;
import tech.pegasys.web3signer.signing.secp256k1.Signer;
import tech.pegasys.web3signer.signing.secp256k1.util.Eth1SignatureUtil;

import java.security.interfaces.ECPublicKey;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.apache.tuweni.bytes.Bytes;
import org.web3j.crypto.Hash;

public class AzureKeyVaultSigner implements Signer {

  public static final String INACCESSIBLE_KEY_ERROR = "Failed to authenticate to vault.";

  private final ECPublicKey publicKey;
  private final SignatureAlgorithm signingAlgo;
  private final boolean needsToHash; // Apply Hash.sha3(data) before signing
  private final CryptographyClient cryptoClient;

  AzureKeyVaultSigner(
      final Bytes publicKey,
      final boolean needsToHash,
      final boolean useDeprecatedSignatureAlgorithm,
      final CryptographyClient cryptoClient) {
    this.publicKey = EthPublicKeyUtils.bytesToECPublicKey(publicKey);
    this.needsToHash = needsToHash;
    this.signingAlgo =
        useDeprecatedSignatureAlgorithm
            ? SignatureAlgorithm.fromString("ECDSA256")
            : SignatureAlgorithm.ES256K;
    this.cryptoClient = cryptoClient;
  }

  @Override
  public Signature sign(byte[] data) {
    return sign(data, needsToHash);
  }

  @Override
  public Signature sign(final byte[] data, final boolean applyHash) {
    final byte[] dataToSign = applyHash ? Hash.sha3(data) : data;

    final SignResult result = cryptoClient.sign(signingAlgo, dataToSign);

    final byte[] signature = result.getSignature();

    if (signature.length != 64) {
      throw new RuntimeException(
          "Invalid signature from the key vault signing service, must be 64 bytes long");
    }

    return Eth1SignatureUtil.deriveSignatureFromP1363Encoded(dataToSign, publicKey, signature);
  }

  @Override
  public ECPublicKey getPublicKey() {
    return publicKey;
  }
}
