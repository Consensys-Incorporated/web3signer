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
package tech.pegasys.web3signer.core.service.jsonrpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError.INVALID_PARAMS;
import static tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError.SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT;

import tech.pegasys.web3signer.core.service.http.handlers.signing.SignerForIdentifier;
import tech.pegasys.web3signer.core.service.jsonrpc.exceptions.JsonRpcException;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.internalresponse.EthSignTransactionResultProvider;
import tech.pegasys.web3signer.signing.SecpArtifactSignature;
import tech.pegasys.web3signer.signing.secp256k1.EthPublicKeyUtils;
import tech.pegasys.web3signer.signing.secp256k1.Signature;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.json.JsonObject;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.support.ParameterDeclarations;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

@ExtendWith(MockitoExtension.class)
public class EthSignTransactionResultProviderTest {

  private static JsonDecoder jsonDecoder;
  private static long chainId;

  @Mock SignerForIdentifier mockSignerForIdentifier;

  @BeforeAll
  static void beforeAll() {
    final ObjectMapper jsonObjectMapper = new ObjectMapper();
    jsonObjectMapper.configure(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES, true);
    jsonObjectMapper.configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, true);
    jsonDecoder = new JsonDecoder(jsonObjectMapper);
    chainId = 44844;
  }

  @ParameterizedTest
  @ArgumentsSource(InvalidParamsProvider.class)
  @NullSource
  public void ifParamIsInvalidExceptionIsThrownWithInvalidParams(final Object params) {
    final EthSignTransactionResultProvider resultProvider =
        new EthSignTransactionResultProvider(chainId, mockSignerForIdentifier, jsonDecoder);

    final JsonRpcRequest request = new JsonRpcRequest("2.0", "eth_signTransaction");
    request.setId(new JsonRpcRequestId(1));
    request.setParams(params);

    final Throwable thrown = catchThrowable(() -> resultProvider.createResponseResult(request));
    assertThat(thrown).isInstanceOf(JsonRpcException.class);
    final JsonRpcException rpcException = (JsonRpcException) thrown;
    assertThat(rpcException.getJsonRpcError()).isEqualTo(INVALID_PARAMS);
  }

  @Test
  public void ifAddressIsNotUnlockedExceptionIsThrownWithSigningNotUnlocked() {

    final EthSignTransactionResultProvider resultProvider =
        new EthSignTransactionResultProvider(chainId, mockSignerForIdentifier, jsonDecoder);

    final JsonRpcRequest request = new JsonRpcRequest("2.0", "eth_signTransaction");
    request.setId(new JsonRpcRequestId(1));
    request.setParams(List.of(getTxParameters()));
    final Throwable thrown = catchThrowable(() -> resultProvider.createResponseResult(request));
    assertThat(thrown).isInstanceOf(JsonRpcException.class);
    final JsonRpcException rpcException = (JsonRpcException) thrown;
    assertThat(rpcException.getJsonRpcError()).isEqualTo(SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT);
  }

  @Test
  public void signatureHasTheExpectedFormat() {
    final Credentials cs =
        Credentials.create("0x1618fc3e47aec7e70451256e033b9edb67f4c469258d8e2fbb105552f141ae41");
    final ECPublicKey key =
        EthPublicKeyUtils.web3JPublicKeyToECPublicKey(cs.getEcKeyPair().getPublicKey());
    final String addr = Keys.getAddress(EthPublicKeyUtils.toHexString(key));

    final BigInteger v = BigInteger.ONE;
    final BigInteger r = BigInteger.TWO;
    final BigInteger s = BigInteger.TEN;
    doReturn(Optional.of(new SecpArtifactSignature(new Signature(v, r, s)).asHex()))
        .when(mockSignerForIdentifier)
        .sign(any(String.class), any(Bytes.class));
    when(mockSignerForIdentifier.isSignerAvailable(any(String.class))).thenReturn(true);
    final EthSignTransactionResultProvider resultProvider =
        new EthSignTransactionResultProvider(chainId, mockSignerForIdentifier, jsonDecoder);

    final JsonRpcRequest request = new JsonRpcRequest("2.0", "eth_signTransaction");
    final int id = 1;
    request.setId(new JsonRpcRequestId(id));
    final JsonObject params = getTxParameters();
    params.put("from", addr);
    request.setParams(params);

    final Object result = resultProvider.createResponseResult(request);
    assertThat(result).isInstanceOf(String.class);
    final String signedTx = (String) result;
    assertThat(signedTx).hasSize(72);
  }

  @Test
  public void nonceNotProvidedExceptionIsThrownWithInvalidParams() {

    final EthSignTransactionResultProvider resultProvider =
        new EthSignTransactionResultProvider(chainId, mockSignerForIdentifier, jsonDecoder);

    final JsonObject params = getTxParameters();
    params.remove("nonce");
    final JsonRpcRequest request = new JsonRpcRequest("2.0", "eth_signTransaction");
    final int id = 1;
    request.setId(new JsonRpcRequestId(id));
    request.setParams(params);
    final Throwable thrown = catchThrowable(() -> resultProvider.createResponseResult(request));
    assertThat(thrown).isInstanceOf(JsonRpcException.class);
    final JsonRpcException rpcException = (JsonRpcException) thrown;
    assertThat(rpcException.getJsonRpcError()).isEqualTo(INVALID_PARAMS);
  }

  @Test
  public void returnsExpectedSignatureForFrontierTransaction() {
    assertThat(executeEthSignTransaction(getTxParameters()))
        .isEqualTo(
            "0xf862468082760094627306090abab3a6e1400e9345bc60c78a8bef57020083015e7ba0e2b345c1c5af05f518e7fd716459fd41d4af3e355b4afb48d8fddc21eae98c13a043975efec1fcfd03f7af77c4a402510981a088765b180bc84163ecba8f01f46d");
  }

  @Test
  public void returnsExpectedSignatureForEip1559Transaction() {
    assertThat(executeEthSignTransaction(get1559TxParameters()))
        .isEqualTo(
            "0x02f86482af2c46010282760094627306090abab3a6e1400e9345bc60c78a8bef570200c080a0c12c61390b8e6c5cded74c3356bdfcace12f2df6ef936bb57b6ae396d430faafa04ac0efe035ef864a63381825e445eb58ad2d01f3927e8c814b5442949847338d");
  }

  @Test
  public void returnsExpectedSignatureForEip4844Transaction() {
    // web3j 6 emits the canonical EIP-4844 signed transaction, 0x03 || rlp([...14 fields...]).
    // web3j 5 additionally wrapped the signed payload in a blob network-wrapper list and
    // appended three empty lists (blobs, commitments, proofs), which was not a valid
    // EIP-4844 signed transaction. The signing preimage (and therefore r/s) is unchanged.
    assertThat(executeEthSignTransaction(get4844TxParameters()))
        .isEqualTo(
            "0x03f88782af2c46010282760094627306090abab3a6e1400e9345bc60c78a8bef570200c003e1a0010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c44401401a099ef021663f2bf3eeee30abad5f798db98f5736fad456b9da3a8c254e65523c1a073123b2465936f4ccaba0e20cad2db613bd48e833cbaad879647333506837239");
  }

  private String executeEthSignTransaction(final JsonObject params) {
    final Credentials cs =
        Credentials.create("0x1618fc3e47aec7e70451256e033b9edb67f4c469258d8e2fbb105552f141ae41");
    final ECPublicKey key =
        EthPublicKeyUtils.web3JPublicKeyToECPublicKey(cs.getEcKeyPair().getPublicKey());
    final String addr = Keys.getAddress(EthPublicKeyUtils.toHexString(key));

    doAnswer(
            answer -> {
              Bytes data = answer.getArgument(1, Bytes.class);
              return signDataForKey(data, cs.getEcKeyPair()).map(SecpArtifactSignature::asHex);
            })
        .when(mockSignerForIdentifier)
        .sign(any(String.class), any(Bytes.class));

    when(mockSignerForIdentifier.isSignerAvailable(any(String.class))).thenReturn(true);

    final EthSignTransactionResultProvider resultProvider =
        new EthSignTransactionResultProvider(chainId, mockSignerForIdentifier, jsonDecoder);

    params.put("from", addr);
    final JsonRpcRequest request = new JsonRpcRequest("2.0", "eth_signTransaction");
    final int id = 1;
    request.setId(new JsonRpcRequestId(id));
    request.setParams(params);

    final Object result = resultProvider.createResponseResult(request);
    assertThat(result).isInstanceOf(String.class);
    return (String) result;
  }

  private static JsonObject getTxParameters() {
    final JsonObject jsonObject = new JsonObject();
    jsonObject.put("from", "0x0c8f735bc186ea3842e640ffdcb474def3e767a0");
    jsonObject.put("to", "0x627306090abaB3A6e1400e9345bC60c78a8BEf57");
    jsonObject.put("gasPrice", "0x0");
    jsonObject.put("gas", "0x7600");
    jsonObject.put("nonce", "0x46");
    jsonObject.put("value", "0x2");
    jsonObject.put("data", "0x0");
    return jsonObject;
  }

  private static JsonObject get1559TxParameters() {
    final JsonObject jsonObject = new JsonObject();
    jsonObject.put("from", "0x0c8f735bc186ea3842e640ffdcb474def3e767a0");
    jsonObject.put("to", "0x627306090abaB3A6e1400e9345bC60c78a8BEf57");
    jsonObject.put("maxPriorityFeePerGas", "0x1");
    jsonObject.put("maxFeePerGas", "0x2");
    jsonObject.put("gas", "0x7600");
    jsonObject.put("nonce", "0x46");
    jsonObject.put("value", "0x2");
    jsonObject.put("data", "0x0");
    return jsonObject;
  }

  private static JsonObject get4844TxParameters() {
    final JsonObject jsonObject = new JsonObject();
    jsonObject.put("from", "0x0c8f735bc186ea3842e640ffdcb474def3e767a0");
    jsonObject.put("to", "0x627306090abaB3A6e1400e9345bC60c78a8BEf57");
    jsonObject.put("maxPriorityFeePerGas", "0x1");
    jsonObject.put("maxFeePerGas", "0x2");
    jsonObject.put("gas", "0x7600");
    jsonObject.put("nonce", "0x46");
    jsonObject.put("value", "0x2");
    jsonObject.put("data", "0x0");
    jsonObject.put(
        "blobVersionedHashes",
        new String[] {"0x010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"});
    jsonObject.put("maxFeePerBlobGas", "0x3");
    return jsonObject;
  }

  private static class InvalidParamsProvider implements ArgumentsProvider {
    @Override
    public Stream<? extends Arguments> provideArguments(
        final ParameterDeclarations parameterDeclarations, final ExtensionContext context) {
      return Stream.of(
          Arguments.of(Collections.emptyList()),
          Arguments.of(Collections.singleton(2)),
          Arguments.of(List.of(1, 2, 3)),
          Arguments.of(new Object()));
    }
  }

  private Optional<SecpArtifactSignature> signDataForKey(Bytes data, ECKeyPair ecKeyPair) {
    final Sign.SignatureData signature = Sign.signPrefixedMessage(data.toArrayUnsafe(), ecKeyPair);
    final SecpArtifactSignature secpArtifactSignature =
        new SecpArtifactSignature(
            new Signature(
                new BigInteger(signature.getV()),
                new BigInteger(1, signature.getR()),
                new BigInteger(1, signature.getS())));
    return Optional.of(secpArtifactSignature);
  }
}
