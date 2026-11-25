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
import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.client.EnclaveException;
import tech.pegasys.web3signer.enclave.client.ProvisioningSession;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Messages.UnwrapDekRequest;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProvisioningTest {
  private static final Duration TIMEOUT = Duration.ofSeconds(30);

  private final ByteArrayOutputStream responses = new ByteArrayOutputStream();
  private InProcessEnclaveSigner signer;
  private EnclaveClient client;

  @BeforeEach
  void start() {
    signer = new InProcessEnclaveSigner();
    client =
        new EnclaveClient(
            (connectTimeout, ioTimeout) ->
                new RecordingConnection(signer.address().connect(connectTimeout, ioTimeout)),
            signer.address().toString(),
            new EnclaveClient.Options(1, 30_000));
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

  /** The release key of a new GET_EVIDENCE. */
  private static byte[] releaseKey(final ProvisioningSession session) {
    return session.getEvidence(new byte[0]).releaseKey();
  }

  /** GET_EVIDENCE, then an envelope of {@code dek} for its release key, then UNWRAP_DEK. */
  private static void release(final ProvisioningSession session, final byte[] dek) {
    final byte[] spki = session.getEvidence(TestEnvelopes.randomBytes(32)).releaseKey();
    session.unwrapDek(
        Protocol.BLOB_FORMAT_CMS,
        TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true));
  }

  private static int result(final Runnable call) {
    try {
      call.run();
      return Protocol.OK;
    } catch (final EnclaveException e) {
      return e.result();
    }
  }

  @Test
  void provisionsKeysThatSign() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    final List<BLSKeyPair> keys = TestKeys.random(5);
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
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
  void unwrapNeedsFreshEvidenceEveryTime() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      assertThat(result(() -> session.unwrapDek(1, new byte[10])))
          .isEqualTo(Protocol.INVALID_STATE);

      // after a success
      final byte[] spki = releaseKey(session);
      final byte[] envelope = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true);
      session.unwrapDek(1, envelope);
      assertThat(result(() -> session.unwrapDek(1, envelope))).isEqualTo(Protocol.INVALID_STATE);

      // after a failure
      releaseKey(session);
      assertThat(result(() -> session.unwrapDek(1, new byte[10])))
          .isEqualTo(Protocol.UNWRAP_FAILED);
      assertThat(result(() -> session.unwrapDek(1, envelope))).isEqualTo(Protocol.INVALID_STATE);

      // an envelope made for an earlier release key fails after a new GET_EVIDENCE
      final byte[] first = releaseKey(session);
      final byte[] forFirst = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(first), dek, true);
      releaseKey(session);
      assertThat(result(() -> session.unwrapDek(1, forFirst))).isEqualTo(Protocol.UNWRAP_FAILED);

      // the DEK of a successful unwrap is gone after a new GET_EVIDENCE
      release(session, dek);
      releaseKey(session);
      assertThat(result(() -> session.loadKeys(seal(dek, TestKeys.random(1)))))
          .isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void everyUnwrapFailureLooksTheSame() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    final List<String> messages = new ArrayList<>();
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      final List<byte[]> blobs = new ArrayList<>();
      blobs.add(new byte[10]);
      // an envelope for another key
      blobs.add(TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(releaseKey(session)), dek, true));
      for (final byte[] blob : blobs) {
        releaseKey(session);
        try {
          session.unwrapDek(1, blob);
        } catch (final EnclaveException e) {
          assertThat(e.result()).isEqualTo(Protocol.UNWRAP_FAILED);
          messages.add(e.detail());
        }
      }
    }
    assertThat(messages).hasSize(2).containsOnly("the release blob did not open");
  }

  @Test
  void unknownBlobFormatIsUnsupportedAndUsesTheKey() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      final byte[] spki = releaseKey(session);
      final byte[] envelope = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true);
      assertThat(result(() -> session.unwrapDek(2, envelope))).isEqualTo(Protocol.UNSUPPORTED);
      assertThat(result(() -> session.unwrapDek(1, envelope))).isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void loadKeysNeedsADataKey() {
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      assertThat(result(() -> session.loadKeys(seal(new byte[32], TestKeys.random(1)))))
          .isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void provisioningStateDiesWithTheConnection() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      release(session, dek);
    }
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      assertThat(result(() -> session.loadKeys(seal(dek, TestKeys.random(1)))))
          .isEqualTo(Protocol.INVALID_STATE);
    }
  }

  @Test
  void everyEvidenceUsesANewReleaseKeyAndTheRequestCarriesOnlyANonce() throws IOException {
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      final Evidence first = session.getEvidence(new byte[] {1});
      final Evidence second = session.getEvidence(new byte[] {1});
      assertThat(first.type()).isEqualTo(Protocol.EVIDENCE_DEV);
      assertThat(first.releaseKey()).hasSize(294).isNotEqualTo(second.releaseKey());
      // dev evidence is the release key itself
      assertThat(first.evidence()).isEqualTo(first.releaseKey());
      assertThat(session.getEvidence(new byte[64]).releaseKey()).hasSize(294);
    }
    try (Connection connection = signer.address().connect(30_000, 30_000)) {
      // the nonce is the only field: a caller key would make it longer than 64 bytes
      final byte[] withKey = Messages.encodeEvidenceRequest(new byte[64]);
      final byte[] longer = Arrays.copyOf(withKey, withKey.length + 294);
      assertThat(exchange(connection, 1, Protocol.GET_EVIDENCE, longer).kind())
          .isEqualTo(Protocol.BAD_REQUEST);
      assertThat(exchange(connection, 2, Protocol.GET_EVIDENCE, new byte[0]).kind())
          .isEqualTo(Protocol.BAD_REQUEST);
    }
  }

  private static Frame exchange(
      final Connection connection, final int requestId, final int opcode, final byte[] body)
      throws IOException {
    Frames.write(connection, new Frame(requestId, opcode, body));
    final Frame response = Frames.read(connection);
    assertThat(response.requestId()).isEqualTo(requestId);
    return response;
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
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      release(session, dek);
      assertThat(session.loadKeys(entries)).isEqualTo(new LoadResult(1, 1, 3));
    }
    for (int i = 1; i < 5; i++) {
      final byte[] key = publicKey(keys.get(i));
      assertThat(result(() -> client.sign(key, new byte[32]))).isEqualTo(Protocol.UNKNOWN_KEY);
    }
    assertThat(client.publicKeys()).hasSize(1);
  }

  @Test
  void aRejectedEntryDoesNotBlockAValidOneForTheSameKey() {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    final BLSKeyPair key = TestKeys.random(1).get(0);
    final SealedKey good = TestEnvelopes.seal(dek, publicKey(key), secret(key));
    final byte[] badTag = good.ciphertext().clone();
    badTag[47] ^= 1;
    final SealedKey bad = new SealedKey(good.publicKey(), good.nonce(), badTag);
    try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
      release(session, dek);
      assertThat(session.loadKeys(List.of(bad, good))).isEqualTo(new LoadResult(1, 0, 1));
    }
    final Bytes root = Bytes.random(32);
    assertThat(Bytes.wrap(client.sign(publicKey(key), root.toArrayUnsafe())))
        .isEqualTo(BLS.sign(key.getSecretKey(), root).toBytesCompressed());
  }

  @Test
  void loadKeysValidatesItsBody() throws IOException {
    final byte[] dek = TestEnvelopes.randomBytes(32);
    try (Connection connection = signer.address().connect(30_000, 30_000)) {
      final Frame evidence =
          exchange(
              connection, 1, Protocol.GET_EVIDENCE, Messages.encodeEvidenceRequest(new byte[0]));
      final byte[] spki = Messages.decodeEvidence(evidence.body()).releaseKey();
      final byte[] blob = TestEnvelopes.envelope(TestEnvelopes.rsaPublicKey(spki), dek, true);
      assertThat(
              exchange(
                      connection,
                      2,
                      Protocol.UNWRAP_DEK,
                      Messages.encodeUnwrapDekRequest(
                          new UnwrapDekRequest(Protocol.BLOB_FORMAT_CMS, blob)))
                  .kind())
          .isEqualTo(Protocol.OK);

      final byte[] request = Messages.encodeLoadKeysRequest(seal(dek, TestKeys.random(1)));
      final byte[] partialEntry = Arrays.copyOf(request, request.length - 1);
      assertThat(exchange(connection, 3, Protocol.LOAD_KEYS, partialEntry).kind())
          .isEqualTo(Protocol.BAD_REQUEST);
      final byte[] noEntries = new byte[4];
      ByteBuffer.wrap(noEntries).order(ByteOrder.LITTLE_ENDIAN).putInt(0, 4);
      assertThat(exchange(connection, 4, Protocol.LOAD_KEYS, noEntries).kind())
          .isEqualTo(Protocol.BAD_REQUEST);
      // the data key survives a malformed request
      final Frame loaded = exchange(connection, 5, Protocol.LOAD_KEYS, request);
      assertThat(Messages.decodeLoadResult(loaded.body())).isEqualTo(new LoadResult(1, 0, 0));
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
      try (ProvisioningSession session = client.openProvisioningSession(TIMEOUT)) {
        session.status();
        release(session, dek);
        session.loadKeys(seal(dek, keys));
        session.loadKeys(seal(dek, keys));
        session.loadKeys(seal(TestEnvelopes.randomBytes(32), TestKeys.random(3)));
        assertThat(result(() -> session.unwrapDek(1, new byte[3])))
            .isEqualTo(Protocol.INVALID_STATE);
        releaseKey(session);
        assertThat(result(() -> session.unwrapDek(1, new byte[3])))
            .isEqualTo(Protocol.UNWRAP_FAILED);
      }
      client.publicKeys();
      for (final BLSKeyPair key : keys) {
        client.sign(publicKey(key), TestEnvelopes.randomBytes(32));
      }
      assertThat(result(() -> client.sign(new byte[48], new byte[32])))
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
      if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
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
