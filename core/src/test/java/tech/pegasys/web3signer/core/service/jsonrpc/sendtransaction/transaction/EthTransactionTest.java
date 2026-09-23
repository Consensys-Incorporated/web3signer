/*
 * Copyright 2019 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.jsonrpc.sendtransaction.transaction;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.web3j.utils.Bytes.trimLeadingZeroes;

import tech.pegasys.web3signer.core.service.jsonrpc.EthSendTransactionJsonParameters;
import tech.pegasys.web3signer.core.service.jsonrpc.JsonRpcRequest;
import tech.pegasys.web3signer.core.service.jsonrpc.JsonRpcRequestId;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.sendtransaction.transaction.EthTransaction;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.crypto.SignedRawTransaction;
import org.web3j.crypto.TransactionDecoder;
import org.web3j.crypto.transaction.type.Transaction1559;
import org.web3j.crypto.transaction.type.Transaction4844;
import org.web3j.crypto.transaction.type.TransactionType;
import org.web3j.rlp.RlpDecoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

public class EthTransactionTest {
  // 131072 zero bytes: one all-zero blob. Its KZG commitment and proof are both the compressed G1
  // point at infinity, and the versioned hash of that commitment is the value below.
  private static final String ZERO_BLOB = "0x" + "00".repeat(131072);
  private static final String G1_POINT_AT_INFINITY = "0xc0" + "00".repeat(47);
  private static final String ZERO_BLOB_VERSIONED_HASH =
      "0x010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014";

  private EthTransaction ethTransaction;

  @BeforeEach
  public void setup() {
    final EthSendTransactionJsonParameters params =
        new EthSendTransactionJsonParameters("0x7577919ae5df4941180eac211965f275cdce314d");
    params.receiver("0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    params.gas("0x76c0");
    params.gasPrice("0x9184e72a000");
    params.nonce("0xe04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f2");
    params.value("0x0");
    params.data(
        "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675");

    ethTransaction =
        new EthTransaction(1337L, params, () -> BigInteger.ZERO, new JsonRpcRequestId(1));
  }

  @Test
  public void rlpEncodesTransaction() {
    final SignatureData signatureData =
        new SignatureData(new byte[] {1}, new byte[] {2}, new byte[] {3});
    final byte[] rlpEncodedBytes = ethTransaction.rlpEncode(signatureData);
    final String rlpString = Numeric.toHexString(rlpEncodedBytes);

    final SignedRawTransaction decodedTransaction =
        (SignedRawTransaction) TransactionDecoder.decode(rlpString);
    assertThat(decodedTransaction.getTo()).isEqualTo("0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    assertThat(decodedTransaction.getGasLimit()).isEqualTo(Numeric.decodeQuantity("0x76c0"));
    assertThat(decodedTransaction.getGasPrice()).isEqualTo(Numeric.decodeQuantity("0x9184e72a000"));
    assertThat(decodedTransaction.getNonce())
        .isEqualTo(
            Numeric.decodeQuantity(
                "0xe04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f2"));
    assertThat(decodedTransaction.getValue()).isEqualTo(Numeric.decodeQuantity("0x0"));
    assertThat(decodedTransaction.getData())
        .isEqualTo(
            "d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675");

    final SignatureData decodedSignatureData = decodedTransaction.getSignatureData();
    assertThat(trimLeadingZeroes(decodedSignatureData.getV())).isEqualTo(new byte[] {1});
    assertThat(trimLeadingZeroes(decodedSignatureData.getR())).isEqualTo(new byte[] {2});
    assertThat(trimLeadingZeroes(decodedSignatureData.getS())).isEqualTo(new byte[] {3});
  }

  @Test
  public void rlpEncodesEip1559Transaction() {
    final EthSendTransactionJsonParameters params =
        new EthSendTransactionJsonParameters("0x7577919ae5df4941180eac211965f275cdce314d");
    params.receiver("0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    params.gas("0x76c0");
    params.maxPriorityFeePerGas("0x9184e72a000");
    params.maxFeePerGas("0x9184e72a001");
    params.nonce("0xe04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f2");
    params.value("0x0");
    params.data(
        "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675");

    ethTransaction =
        new EthTransaction(1337L, params, () -> BigInteger.ZERO, new JsonRpcRequestId(1));

    final SignatureData signatureData = null;
    final byte[] rlpEncodedBytes = ethTransaction.rlpEncode(signatureData);
    final String rlpString = Numeric.toHexString(prependEip1559TransactionType(rlpEncodedBytes));

    final Transaction1559 decodedTransaction =
        (Transaction1559) TransactionDecoder.decode(rlpString).getTransaction();
    assertThat(decodedTransaction.getTo()).isEqualTo("0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    assertThat(decodedTransaction.getGasLimit()).isEqualTo(Numeric.decodeQuantity("0x76c0"));
    assertThat(decodedTransaction.getMaxPriorityFeePerGas())
        .isEqualTo(Numeric.decodeQuantity("0x9184e72a000"));
    assertThat(decodedTransaction.getMaxFeePerGas())
        .isEqualTo(Numeric.decodeQuantity("0x9184e72a001"));
    assertThat(decodedTransaction.getNonce())
        .isEqualTo(
            Numeric.decodeQuantity(
                "0xe04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f2"));
    assertThat(decodedTransaction.getValue()).isEqualTo(Numeric.decodeQuantity("0x0"));
    assertThat(decodedTransaction.getData())
        .isEqualTo(
            "d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675");
  }

  private static byte[] prependEip1559TransactionType(byte[] bytesToSign) {
    return ByteBuffer.allocate(bytesToSign.length + 1)
        .put(TransactionType.EIP1559.getRlpType())
        .put(bytesToSign)
        .array();
  }

  @Test
  public void rlpEncodesEip4844Transaction() {
    final EthSendTransactionJsonParameters params = eip4844Parameters();
    params.blobVersionedHashes(new String[] {ZERO_BLOB_VERSIONED_HASH});
    ethTransaction =
        new EthTransaction(1337L, params, () -> BigInteger.ZERO, new JsonRpcRequestId(1));

    final SignatureData signatureData = null;
    final byte[] rlpEncodedBytes = ethTransaction.rlpEncode(signatureData);
    final String rlpString = Numeric.toHexString(prependEip4844TransactionType(rlpEncodedBytes));

    final Transaction4844 decodedTransaction =
        (Transaction4844) TransactionDecoder.decode(rlpString).getTransaction();
    assertThat(decodedTransaction.getTo()).isEqualTo("0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    assertThat(decodedTransaction.getGasLimit()).isEqualTo(Numeric.decodeQuantity("0x76c0"));
    assertThat(decodedTransaction.getMaxPriorityFeePerGas())
        .isEqualTo(Numeric.decodeQuantity("0x9184e72a000"));
    assertThat(decodedTransaction.getMaxFeePerGas())
        .isEqualTo(Numeric.decodeQuantity("0x9184e72a001"));

    assertThat(decodedTransaction.getVersionedHashes().get(0).toHexString())
        .isEqualTo(ZERO_BLOB_VERSIONED_HASH);
    assertThat(decodedTransaction.getMaxFeePerBlobGas())
        .isEqualTo(Numeric.decodeQuantity("0x9184e72a002"));
  }

  @Test
  public void signedEip4844TransactionWithBlobsIsEncodedAsNetworkWrapper() {
    ethTransaction =
        new EthTransaction(
            1337L, eip4844Parameters(), () -> BigInteger.ZERO, new JsonRpcRequestId(1));
    final SignatureData signatureData =
        new SignatureData((byte) 27, new byte[] {2}, new byte[] {3});

    // eth_sendRawTransaction only accepts blob transactions in the EIP-4844 network form:
    // rlp([tx_payload_body, blobs, commitments, proofs])
    final RlpList wrapper =
        (RlpList) RlpDecoder.decode(ethTransaction.rlpEncode(signatureData)).getValues().get(0);
    assertThat(wrapper.getValues()).hasSize(4);

    final List<RlpType> body = ((RlpList) wrapper.getValues().get(0)).getValues();
    final List<RlpType> blobs = ((RlpList) wrapper.getValues().get(1)).getValues();
    final List<RlpType> commitments = ((RlpList) wrapper.getValues().get(2)).getValues();
    final List<RlpType> proofs = ((RlpList) wrapper.getValues().get(3)).getValues();

    assertThat(body).hasSize(14); // 11 transaction fields plus y_parity, r and s
    assertThat(blobs).hasSize(1);
    assertThat(((RlpString) blobs.get(0)).asString()).isEqualTo(ZERO_BLOB);
    assertThat(commitments).hasSize(1);
    assertThat(((RlpString) commitments.get(0)).asString()).isEqualTo(G1_POINT_AT_INFINITY);
    assertThat(proofs).hasSize(1);
    assertThat(((RlpString) proofs.get(0)).asString()).isEqualTo(G1_POINT_AT_INFINITY);
    // blob_versioned_hashes (field 10) must be derived from the blob's commitment
    final List<RlpType> versionedHashes = ((RlpList) body.get(10)).getValues();
    assertThat(versionedHashes).hasSize(1);
    assertThat(((RlpString) versionedHashes.get(0)).asString()).isEqualTo(ZERO_BLOB_VERSIONED_HASH);
  }

  private static EthSendTransactionJsonParameters eip4844Parameters() {
    final EthSendTransactionJsonParameters params =
        new EthSendTransactionJsonParameters("0x7577919ae5df4941180eac211965f275cdce314d");
    params.receiver("0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    params.gas("0x76c0");
    params.maxPriorityFeePerGas("0x9184e72a000");
    params.maxFeePerGas("0x9184e72a001");
    params.nonce("0xe04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f2");
    params.value("0x0");
    params.data(
        "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675");
    params.blobs(new String[] {ZERO_BLOB});
    params.maxFeePerBlobGas("0x9184e72a002");
    return params;
  }

  private static byte[] prependEip4844TransactionType(byte[] bytesToSign) {
    return ByteBuffer.allocate(bytesToSign.length + 1)
        .put(TransactionType.EIP4844.getRlpType())
        .put(bytesToSign)
        .array();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void createsJsonRequest() {
    final JsonRpcRequestId id = new JsonRpcRequestId(2);
    final String transactionString =
        "0xf90114a0e04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f28609184e72a0008276c094d46e8dd67c5d32be8058bb8eb970870f0724456704a9d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f07244567536a0fe72a92aede764ce41d06b163d28700b58e5ee8bb1af91d9d54979ea3bdb3e7ea046ae10c94c322fa44ddceb86677c2cd6cc17dfbd766924f41d10a244c512996dac5a6c617045736c3971444c50792f6538382b2f36797643554556497648383379304e3441367748754b58493dedac4756386d30565a41636359474141594d42755951744b456a3058747058656177324150636f426d744132773d8a72657374726963746564";
    final JsonRpcRequest jsonRpcRequest = ethTransaction.jsonRpcRequest(transactionString, id);

    assertThat(jsonRpcRequest.getMethod()).isEqualTo("eth_sendRawTransaction");
    assertThat(jsonRpcRequest.getVersion()).isEqualTo("2.0");
    assertThat(jsonRpcRequest.getId()).isEqualTo(id);
    final List<String> params = (List<String>) jsonRpcRequest.getParams();
    assertThat(params).isEqualTo(singletonList(transactionString));
  }
}
