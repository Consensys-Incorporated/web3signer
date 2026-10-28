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
package tech.pegasys.web3signer.tests.eth1rpc.signing;

import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError.SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT;

import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ConfigurationChainId;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcErrorResponse;
import tech.pegasys.web3signer.dsl.Account;
import tech.pegasys.web3signer.dsl.signer.SignerConfiguration;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.signer.SignerResponse;
import tech.pegasys.web3signer.signing.secp256k1.util.AddressUtil;
import tech.pegasys.web3signer.tests.eth1rpc.Eth1RpcAcceptanceTestBase;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.utils.Convert;
import org.web3j.utils.Convert.Unit;

public class ValueTransferAcceptanceTest extends Eth1RpcAcceptanceTestBase {
  private static final Logger LOG = LogManager.getLogger();
  private static final String RECIPIENT = "0x1b00ba00ca00bb00aa00bc00be00ac00ca00da00";
  private static final long FIFTY_TRANSACTIONS = 50;
  private static final String FRONTIER = "0x0";
  private static final String EIP1559 = "0x2";

  @BeforeEach
  public void setup(final TestInfo testInfo) {
    LOG.info("--- Starting Besu for test {}", testInfo.getDisplayName());
    startBesu();
    final SignerConfiguration web3SignerConfiguration =
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(keyFileTempDir)
            .withMode("eth1")
            .withDownstreamHttpPort(besu.ports().getHttpRpc())
            .withChainIdProvider(new ConfigurationChainId(2018))
            .build();

    startSigner(web3SignerConfiguration);
  }

  @Test
  public void valueTransferFrontier() {
    transferFrontier();
  }

  private void transferFrontier() {
    final BigInteger transferAmountWei = Convert.toWei("1.75", Unit.ETHER).toBigIntegerExact();
    final BigInteger startBalance = besu.accounts().balance(RECIPIENT);
    final Transaction frontierTransaction =
        Transaction.createEtherTransaction(
            richBenefactor().address(),
            null,
            GAS_PRICE,
            INTRINSIC_GAS,
            RECIPIENT,
            transferAmountWei);

    final String hash = signer.transactions().submit(frontierTransaction);
    besu.transactions().awaitBlockContaining(hash);

    final BigInteger expectedEndBalance = startBalance.add(transferAmountWei);
    final BigInteger actualEndBalance = besu.accounts().balance(RECIPIENT);
    assertThat(actualEndBalance).isEqualTo(expectedEndBalance);

    // assert tx is FRONTIER type
    final var receipt = besu.transactions().getTransactionReceipt(hash).orElseThrow();
    assertThat(receipt.getType()).isEqualTo(FRONTIER);
  }

  @Test
  public void valueTransferEip1559() {
    final BigInteger transferAmountWei = Convert.toWei("1.75", Unit.ETHER).toBigIntegerExact();
    final BigInteger startBalance = besu.accounts().balance(RECIPIENT);
    final Transaction eip1559Transaction =
        new Transaction(
            richBenefactor().address(),
            null,
            null,
            INTRINSIC_GAS,
            RECIPIENT,
            transferAmountWei,
            null,
            2018L,
            GAS_PRICE,
            GAS_PRICE);

    final String hash = signer.transactions().submit(eip1559Transaction);
    besu.transactions().awaitBlockContaining(hash);

    final BigInteger expectedEndBalance = startBalance.add(transferAmountWei);
    final BigInteger actualEndBalance = besu.accounts().balance(RECIPIENT);
    assertThat(actualEndBalance).isEqualTo(expectedEndBalance);

    // assert tx is EIP1559 type
    final var receipt = besu.transactions().getTransactionReceipt(hash).orElseThrow();
    assertThat(receipt.getType()).isEqualTo(EIP1559);
  }

  @Test
  public void valueTransferWithFromWithout0xPrefix() {
    final BigInteger transferAmountWei = Convert.toWei("1.75", Unit.ETHER).toBigIntegerExact();
    final BigInteger startBalance = besu.accounts().balance(RECIPIENT);
    final Transaction transaction =
        Transaction.createEtherTransaction(
            AddressUtil.remove0xPrefix(richBenefactor().address()),
            null,
            GAS_PRICE,
            INTRINSIC_GAS,
            RECIPIENT,
            transferAmountWei);

    final String hash = signer.transactions().submit(transaction);
    besu.transactions().awaitBlockContaining(hash);

    final BigInteger expectedEndBalance = startBalance.add(transferAmountWei);
    final BigInteger actualEndBalance = besu.accounts().balance(RECIPIENT);
    assertThat(actualEndBalance).isEqualTo(expectedEndBalance);
  }

  @Test
  public void valueTransferFromAccountWithInsufficientFunds() {
    final String recipientAddress = "0x1b11ba11ca11bb11aa11bc11be11ac11ca11da11";
    final BigInteger senderStartBalance = besu.accounts().balance(richBenefactor());
    final BigInteger recipientStartBalance = besu.accounts().balance(recipientAddress);
    final BigInteger transferAmountWei = senderStartBalance.add(BigInteger.ONE);
    final Transaction transaction =
        Transaction.createEtherTransaction(
            richBenefactor().address(),
            richBenefactor().nextNonce(),
            GAS_PRICE,
            INTRINSIC_GAS,
            recipientAddress,
            transferAmountWei);

    final SignerResponse<JsonRpcErrorResponse> signerResponse =
        signer.transactions().submitExceptional(transaction);
    assertThat(signerResponse.jsonRpc().getError())
        .isEqualTo(JsonRpcError.INSUFFICIENT_FUNDS_FOR_TRANSFER);

    final BigInteger senderEndBalance = besu.accounts().balance(richBenefactor());
    final BigInteger recipientEndBalance = besu.accounts().balance(recipientAddress);
    assertThat(senderEndBalance).isEqualTo(senderStartBalance);
    assertThat(recipientEndBalance).isEqualTo(recipientStartBalance);
  }

  @Test
  public void senderIsNotUnlockedAccount() {
    final Account sender = new Account("0x223b55228fb22b89f2216b7222e5522b8222bd22");
    final String recipientAddress = "0x1b22ba22ca22bb22aa22bc22be22ac22ca22da22";
    final BigInteger senderStartBalance = besu.accounts().balance(sender);
    final BigInteger recipientStartBalance = besu.accounts().balance(recipientAddress);
    final Transaction transaction =
        Transaction.createEtherTransaction(
            sender.address(),
            sender.nextNonce(),
            GAS_PRICE,
            INTRINSIC_GAS,
            recipientAddress,
            senderStartBalance);

    final SignerResponse<JsonRpcErrorResponse> signerResponse =
        signer.transactions().submitExceptional(transaction);
    assertThat(signerResponse.status()).isEqualTo(BAD_REQUEST);
    assertThat(signerResponse.jsonRpc().getError())
        .isEqualTo(SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT);

    final BigInteger senderEndBalance = besu.accounts().balance(sender);
    final BigInteger recipientEndBalance = besu.accounts().balance(recipientAddress);
    assertThat(senderEndBalance).isEqualTo(senderStartBalance);
    assertThat(recipientEndBalance).isEqualTo(recipientStartBalance);
  }

  @Test
  public void multipleValueTransfers() {
    final BigInteger transferAmountWei = Convert.toWei("1", Unit.ETHER).toBigIntegerExact();
    final BigInteger startBalance = besu.accounts().balance(RECIPIENT);
    final Transaction transaction =
        Transaction.createEtherTransaction(
            richBenefactor().address(),
            null,
            GAS_PRICE,
            INTRINSIC_GAS,
            RECIPIENT,
            transferAmountWei);

    List<String> hashes = new ArrayList<>();
    for (int i = 0; i < FIFTY_TRANSACTIONS; i++) {
      hashes.add(signer.transactions().submit(transaction));
    }

    hashes.forEach(hash -> besu.transactions().awaitBlockContaining(hash));

    final BigInteger endBalance = besu.accounts().balance(RECIPIENT);
    final BigInteger numberOfTransactions = BigInteger.valueOf(FIFTY_TRANSACTIONS);
    assertThat(endBalance)
        .isEqualTo(startBalance.add(transferAmountWei.multiply(numberOfTransactions)));
  }

  @Test
  public void valueTransferNonceTooLow() {
    transferFrontier(); // increments the nonce
    final BigInteger transferAmountWei = Convert.toWei("15.5", Unit.ETHER).toBigIntegerExact();
    final Transaction transaction =
        Transaction.createEtherTransaction(
            richBenefactor().address(),
            BigInteger.ZERO,
            GAS_PRICE,
            INTRINSIC_GAS,
            RECIPIENT,
            transferAmountWei);

    final SignerResponse<JsonRpcErrorResponse> jsonRpcErrorResponseSignerResponse =
        signer.transactions().submitExceptional(transaction);

    assertThat(jsonRpcErrorResponseSignerResponse.jsonRpc().getError())
        .isEqualTo(JsonRpcError.NONCE_TOO_LOW);
  }
}
