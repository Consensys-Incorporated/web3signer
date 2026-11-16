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
package tech.pegasys.web3signer.enclave.signer;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.enclave.protocol.Connection;
import tech.pegasys.web3signer.enclave.protocol.EnclaveClient;
import tech.pegasys.web3signer.enclave.protocol.EnclaveException;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Payloads;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.protocol.ProvisioningSession;
import tech.pegasys.web3signer.enclave.protocol.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Transports;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProvisioningTest {
  private final ByteArrayOutputStream responses = new ByteArrayOutputStream();
  private InProcessEnclaveSigner signer;
  private EnclaveClient client;

  @BeforeEach
  void start() {
    signer = new InProcessEnclaveSigner();
    client =
        new EnclaveClient(
            timeout -> new RecordingConnection(Transports.connect(signer.address(), timeout)),
            signer.address().toString(),
            new EnclaveClient.Options(1, 8, 30_000));
  }

  @AfterEach
  void stop() {
    client.close();
    signer.close();
  }

  private static byte[] secret(final BLSKeyPair key) {
    return key.getSecretKey().toBytes().toArrayUnsafe();
  }

  private static byte[] publicKey(final BLSKeyPair key) {
    return key.getPublicKey().toBytesCompressed().toArrayUnsafe();
  }

  private static List<SealedKey> seal(final byte[] dek, final List<BLSKeyPair> keys) {
    final List<SealedKey> sealed = new ArrayList<>();
    for (final BLSKeyPair key : keys) {
      sealed.add(TestEnvelopes.seal(dek, publicKey(key), secret(key)));
    }
    return sealed;
  }

  /** ATTEST, then an envelope of {@code dek} for the attested key, then UNWRAP_DEK. */
  private static void release(final ProvisioningSession session, final byte[] dek) {
    final byte[] spki = session.attest(TestEnvelopes.randomBytes(32));
    session.unwrapDek(
        Protocol.BLOB_FORMAT_CMS,
        TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true));
  }

  private static int status(final Runnable call) {
    try {
      call.run();
      return Protocol.OK;
    } catch (final EnclaveException e) {
      return e.status();
    }
  }

  @Test
  void provisionsKeysThatSign() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    final List<BLSKeyPair> keys = TestKeys.random(5);
    try (ProvisioningSession session = client.openProvisioningSession()) {
      release(session, dek);
      assertThat(session.loadKeys(seal(dek, keys))).isEqualTo(new LoadResult(5, 0, 0));
      assertThat(session.loadKeys(seal(dek, keys))).isEqualTo(new LoadResult(0, 5, 0));
      assertThat(session.status().keyCount()).isEqualTo(5);
    }
    final Bytes root = Bytes.random(32);
    for (final BLSKeyPair key : keys) {
      final byte[] signature = client.sign(publicKey(key), root.toArrayUnsafe());
      assertThat(Bytes.wrap(signature))
          .isEqualTo(BLS.sign(key.getSecretKey(), root).toBytesCompressed());
    }
    assertThat(client.publicKeys()).hasSize(5);
  }

  @Test
  void unwrapNeedsAFreshAttestationEveryTime() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession()) {
      assertThat(status(() -> session.unwrapDek(1, new byte[10])))
          .isEqualTo(Protocol.INVALID_STATE);

      // after a success
      final byte[] spki = session.attest(new byte[0]);
      final byte[] envelope = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true);
      session.unwrapDek(1, envelope);
      assertThat(status(() -> session.unwrapDek(1, envelope))).isEqualTo(Protocol.INVALID_STATE);

      // after a failure
      session.attest(new byte[0]);
      assertThat(status(() -> session.unwrapDek(1, new byte[10])))
          .isEqualTo(Protocol.UNWRAP_FAILED);
      assertThat(status(() -> session.unwrapDek(1, envelope))).isEqualTo(Protocol.INVALID_STATE);

      // an envelope made for an earlier ATTEST fails after a new ATTEST
      final byte[] first = session.attest(new byte[0]);
      final byte[] forFirst = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(first), dek, true);
      session.attest(new byte[0]);
      assertThat(status(() -> session.unwrapDek(1, forFirst))).isEqualTo(Protocol.UNWRAP_FAILED);

      // the DEK of a successful unwrap is gone after a new ATTEST
      release(session, dek);
      session.attest(new byte[0]);
      assertThat(status(() -> session.loadKeys(seal(dek, TestKeys.random(1)))))
          .isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void unknownBlobFormatIsUnsupportedAndUsesTheKey() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession()) {
      final byte[] spki = session.attest(new byte[0]);
      final byte[] envelope = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true);
      assertThat(status(() -> session.unwrapDek(2, envelope))).isEqualTo(Protocol.UNSUPPORTED);
      assertThat(status(() -> session.unwrapDek(1, envelope))).isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void loadKeysNeedsADataKey() {
    try (ProvisioningSession session = client.openProvisioningSession()) {
      assertThat(status(() -> session.loadKeys(seal(new byte[32], TestKeys.random(1)))))
          .isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void provisioningStateDiesWithTheConnection() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession()) {
      release(session, dek);
    }
    try (ProvisioningSession session = client.openProvisioningSession()) {
      assertThat(status(() -> session.loadKeys(seal(dek, TestKeys.random(1)))))
          .isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void everyAttestationUsesANewKeyAndTheRequestCarriesOnlyANonce() throws IOException {
    try (ProvisioningSession session = client.openProvisioningSession()) {
      final byte[] first = session.attest(new byte[] {1});
      final byte[] second = session.attest(new byte[] {1});
      assertThat(first).hasSize(294).isNotEqualTo(second);
      assertThat(session.attest(new byte[64])).hasSize(294);
    }
    try (Connection connection = Transports.connect(signer.address(), 30_000)) {
      // a nonce length of 2 followed by 2 + 294 bytes: there is no room for a caller key
      final byte[] payload = new byte[1 + 2 + 294];
      payload[0] = 2;
      write(connection, Frames.encode(Protocol.ATTEST, 1, payload));
      assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);
      final byte[] tooLong = new byte[1 + 65];
      tooLong[0] = 65;
      write(connection, Frames.encode(Protocol.ATTEST, 2, tooLong));
      assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);
      write(connection, Frames.encode(Protocol.ATTEST, 3, new byte[0]));
      assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);
    }
  }

  private static void write(final Connection connection, final byte[] bytes) throws IOException {
    connection.write(bytes, 0, bytes.length);
  }

  @Test
  void invalidEntriesAreRejectedAndNotSignable() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    final List<BLSKeyPair> keys = TestKeys.random(5);
    final SealedKey good = TestEnvelopes.seal(dek, publicKey(keys.get(0)), secret(keys.get(0)));
    final byte[] badTag = good.ciphertext().clone();
    badTag[47] ^= 1;
    final List<SealedKey> entries =
        List.of(
            good,
            // wrong tag
            new SealedKey(good.publicKey(), good.nonce(), badTag),
            // another key's public key: the tag verifies, the derived key does not match
            TestEnvelopes.seal(dek, publicKey(keys.get(2)), secret(keys.get(1))),
            // sealed under another data key
            TestEnvelopes.seal(
                TestEnvelopes.randomBytes(32), publicKey(keys.get(3)), secret(keys.get(3))),
            // not a valid scalar
            TestEnvelopes.seal(dek, publicKey(keys.get(4)), new byte[32]));
    try (ProvisioningSession session = client.openProvisioningSession()) {
      release(session, dek);
      assertThat(session.loadKeys(entries)).isEqualTo(new LoadResult(1, 1, 3));
    }
    for (int i = 1; i < 5; i++) {
      final byte[] key = publicKey(keys.get(i));
      assertThat(status(() -> client.sign(key, new byte[32]))).isEqualTo(Protocol.UNKNOWN_KEY);
    }
    assertThat(client.publicKeys()).hasSize(1);
  }

  @Test
  void loadKeysValidatesItsFraming() throws IOException {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession()) {
      release(session, dek);
    }
    try (Connection connection = Transports.connect(signer.address(), 30_000)) {
      write(connection, Frames.encode(Protocol.ATTEST, 1, new byte[] {0}));
      final byte[] spki = Payloads.decodeAttestation(Frames.read(connection).payload());
      write(
          connection,
          Frames.encode(
              Protocol.UNWRAP_DEK,
              2,
              Payloads.unwrapDekRequest(
                  1, TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true))));
      assertThat(Frames.read(connection).payload()).containsExactly(Protocol.OK);
      final byte[] wrongCount = Payloads.loadKeysRequest(seal(dek, TestKeys.random(1)));
      wrongCount[3] = 2;
      write(connection, Frames.encode(Protocol.LOAD_KEYS, 3, wrongCount));
      assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);
      write(connection, Frames.encode(Protocol.LOAD_KEYS, 4, new byte[4]));
      assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);
    }
  }

  @Test
  void noResponseAndNoLogLineCarriesASecretOrTheDataKey() {
    final PrintStream originalErr = System.err;
    final ByteArrayOutputStream log = new ByteArrayOutputStream();
    final byte[] dek = TestEnvelopes.randomBytes(32);
    final List<BLSKeyPair> keys = TestKeys.random(20);
    System.setErr(new PrintStream(log, true, StandardCharsets.UTF_8));
    try {
      try (ProvisioningSession session = client.openProvisioningSession()) {
        session.status();
        release(session, dek);
        session.loadKeys(seal(dek, keys));
        session.loadKeys(seal(dek, keys));
        session.loadKeys(seal(TestEnvelopes.randomBytes(32), TestKeys.random(3)));
        assertThat(status(() -> session.unwrapDek(1, new byte[3])))
            .isEqualTo(Protocol.INVALID_STATE);
        session.attest(new byte[0]);
        assertThat(status(() -> session.unwrapDek(1, new byte[3])))
            .isEqualTo(Protocol.UNWRAP_FAILED);
      }
      client.publicKeys();
      for (final BLSKeyPair key : keys) {
        client.sign(publicKey(key), TestEnvelopes.randomBytes(32));
      }
      assertThat(status(() -> client.sign(new byte[48], new byte[32])))
          .isEqualTo(Protocol.UNKNOWN_KEY);
    } finally {
      System.setErr(originalErr);
    }

    final byte[] captured = responses.toByteArray();
    final String logText = log.toString(StandardCharsets.UTF_8);
    assertThat(captured.length).isGreaterThan(1000);
    assertThat(logText).contains("load keys");
    final List<byte[]> secrets = new ArrayList<>();
    secrets.add(dek);
    keys.forEach(key -> secrets.add(secret(key)));
    for (final byte[] secret : secrets) {
      assertThat(Bytes.wrap(captured).toUnprefixedHexString())
          .doesNotContain(HexFormat.of().formatHex(secret));
      assertThat(contains(captured, secret)).isFalse();
      assertThat(logText.toLowerCase(Locale.ROOT))
          .doesNotContain(HexFormat.of().formatHex(secret))
          .doesNotContain(HexFormat.of().formatHex(secret, 0, 8));
    }
  }

  private static boolean contains(final byte[] haystack, final byte[] needle) {
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      if (java.util.Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
        return true;
      }
    }
    return false;
  }

  /** Records every byte the client reads: all response frames of all opcodes. */
  private final class RecordingConnection implements Connection {
    private final Connection delegate;

    RecordingConnection(final Connection delegate) {
      this.delegate = delegate;
    }

    @Override
    public int read(final byte[] buffer, final int offset, final int length) throws IOException {
      final int n = delegate.read(buffer, offset, length);
      if (n > 0) {
        synchronized (responses) {
          responses.write(buffer, offset, n);
        }
      }
      return n;
    }

    @Override
    public void write(final byte[] buffer, final int offset, final int length) throws IOException {
      delegate.write(buffer, offset, length);
    }

    @Override
    public void close() {
      delegate.close();
    }
  }
}
