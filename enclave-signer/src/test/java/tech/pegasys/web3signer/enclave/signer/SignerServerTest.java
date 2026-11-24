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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.client.EnclaveException;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.PageRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.SignRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.Status;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.Connection;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;
import tech.pegasys.web3signer.enclave.transport.Listener;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SignerServerTest {
  private static final Blst BLST = new Blst(BlstTestLibrary.path());

  private final List<AutoCloseable> resources = new ArrayList<>();
  private SignerServer server;
  private final Random random = new Random(1);

  @AfterEach
  void tearDown() throws Exception {
    for (final AutoCloseable resource : resources.reversed()) {
      resource.close();
    }
  }

  private SignerServer startServer() throws IOException {
    final Listener tcp = EnclaveAddress.parseListen("tcp:127.0.0.1:0").listen();
    server =
        new SignerServer(tcp, BLST, new DevEvidenceProvider(), Protocol.PLATFORM_DEV, 64, "test");
    server.start();
    resources.add(server);
    return server;
  }

  private EnclaveClient client() {
    final EnclaveClient client =
        EnclaveClient.create(server.address(), new EnclaveClient.Options(1, 5000));
    resources.add(client);
    return client;
  }

  private Connection connect() throws IOException {
    final Connection connection = server.address().connect(5000, 5000);
    resources.add(connection);
    return connection;
  }

  private static void send(final Connection connection, final byte[] bytes) throws IOException {
    connection.write(bytes, 0, bytes.length);
  }

  /** Sends one request frame and reads the response. */
  private static Frame exchange(
      final Connection connection, final int requestId, final int opcode, final byte[] body)
      throws IOException {
    Frames.write(connection, new Frame(requestId, opcode, body));
    final Frame response = Frames.read(connection);
    assertThat(response.requestId()).isEqualTo(requestId);
    return response;
  }

  private static byte[] publicKey(final BLSKeyPair key) {
    return key.getPublicKey().toBytesCompressed().toArrayUnsafe();
  }

  @Test
  void statusReportsThePlatformAndKeyCount() throws IOException {
    startServer();
    TestKeys.load(server.keys(), BLST, TestKeys.random(2));
    final Status status = client().status();
    assertThat(status.protocolVersion()).isEqualTo(Protocol.VERSION);
    assertThat(status.platformName()).isEqualTo("dev");
    assertThat(status.keyCount()).isEqualTo(2);
    assertThat(status.version()).isEqualTo("test");
    assertThat(status.cpus()).isEqualTo(Runtime.getRuntime().availableProcessors());
    assertThat(status.bootId()).hasSize(32);
  }

  @Test
  void signaturesVerify() throws IOException {
    startServer();
    final List<BLSKeyPair> keys = TestKeys.random(3);
    TestKeys.load(server.keys(), BLST, keys);
    final EnclaveClient client = client();
    final Bytes root = Bytes.random(32);
    for (final BLSKeyPair key : keys) {
      final byte[] signature = client.sign(publicKey(key), root.toArrayUnsafe());
      final BLSSignature blsSignature = BLSSignature.fromBytesCompressed(Bytes.wrap(signature));
      assertThat(BLS.verify(key.getPublicKey(), root, blsSignature)).isTrue();
      assertThat(blsSignature).isEqualTo(BLS.sign(key.getSecretKey(), root));
    }
  }

  @Test
  void unknownKeyIsRefused() throws IOException {
    startServer();
    TestKeys.load(server.keys(), BLST, TestKeys.random(1));
    final byte[] other = publicKey(TestKeys.random(1).get(0));
    assertThatThrownBy(() -> client().sign(other, new byte[32]))
        .isInstanceOfSatisfying(
            EnclaveException.class,
            e -> {
              assertThat(e.result()).isEqualTo(Protocol.UNKNOWN_KEY);
              assertThat(e.detail()).isEqualTo("the enclave does not hold this key");
            });
  }

  @Test
  void publicKeyPagesAreCompleteAndOrdered() throws IOException {
    startServer();
    final int count = 20_000;
    final byte[] keys = new byte[count * 48];
    random.nextBytes(keys);
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment scalars = arena.allocate(count * 32L, 8);
      assertThat(server.keys().addAll(keys, scalars, count)).isEqualTo(count);
    }
    final List<byte[]> listed = client().publicKeys();
    assertThat(listed).hasSize(count);
    for (int i = 0; i < count; i++) {
      assertThat(listed.get(i)).isEqualTo(Arrays.copyOfRange(keys, i * 48, i * 48 + 48));
    }

    final Connection connection = connect();
    final Frame tail =
        exchange(
            connection,
            1,
            Protocol.GET_PUBLIC_KEYS,
            Messages.encodePageRequest(new PageRequest(19_998, 5)));
    assertThat(tail.kind()).isEqualTo(Protocol.OK);
    final Messages.PublicKeysPage page = Messages.decodePublicKeys(tail.body());
    assertThat(page.total()).isEqualTo(count);
    assertThat(page.publicKeys()).hasSize(2);

    final Frame badLimit = exchange(connection, 2, Protocol.GET_PUBLIC_KEYS, new byte[16]);
    assertThat(badLimit.kind()).isEqualTo(Protocol.BAD_REQUEST);
    assertThat(Messages.decodeErrorMessage(badLimit.body())).contains("limit");
  }

  @Test
  void connectionAboveTheMaximumIsRefused() throws IOException {
    startServer();
    for (int i = 0; i < 64; i++) {
      final Connection connection = connect();
      assertThat(exchange(connection, i, Protocol.STATUS, Messages.encodeStatusRequest()).kind())
          .isEqualTo(Protocol.OK);
    }
    final Connection extra = connect();
    Frames.write(extra, new Frame(65, Protocol.STATUS, Messages.encodeStatusRequest()));
    assertThat(readOrEnd(extra)).isEqualTo(-1);
  }

  /** Reads one byte; -1 when the peer closed or reset the connection. */
  private static int readOrEnd(final Connection connection) {
    try {
      return connection.read(new byte[1], 0, 1);
    } catch (final IOException e) {
      return -1;
    }
  }

  @Test
  void pipelinedRequestsAreAnsweredInOrder() throws IOException {
    startServer();
    final List<BLSKeyPair> keys = TestKeys.random(8);
    TestKeys.load(server.keys(), BLST, keys);
    final Bytes root = Bytes.random(32);
    final Connection connection = connect();
    for (int i = 0; i < 8; i++) {
      final byte[] body =
          Messages.encodeSignRequest(new SignRequest(publicKey(keys.get(i)), root.toArrayUnsafe()));
      Frames.write(connection, new Frame(100 + i, Protocol.SIGN, body));
    }
    for (int i = 0; i < 8; i++) {
      final Frame response = Frames.read(connection);
      assertThat(response.requestId()).isEqualTo(100 + i);
      assertThat(response.kind()).isEqualTo(Protocol.OK);
      assertThat(Bytes.wrap(Messages.decodeSignature(response.body())))
          .isEqualTo(BLS.sign(keys.get(i).getSecretKey(), root).toBytesCompressed());
    }
  }

  @Test
  void malformedRequestsAreBadRequestsAndKeepTheConnection() throws IOException {
    startServer();
    final Connection connection = connect();
    // SIGN takes a 32-byte signing root and nothing else
    assertThat(exchange(connection, 1, Protocol.SIGN, new byte[79]).kind())
        .isEqualTo(Protocol.BAD_REQUEST);
    assertThat(exchange(connection, 2, Protocol.SIGN, new byte[81]).kind())
        .isEqualTo(Protocol.BAD_REQUEST);
    final Frame unknown = exchange(connection, 3, 0x7f, new byte[0]);
    assertThat(unknown.kind()).isEqualTo(Protocol.UNSUPPORTED);
    assertThat(Messages.decodeErrorMessage(unknown.body())).isEqualTo("unknown opcode 0x7f");
    assertThat(exchange(connection, 4, Protocol.STATUS, new byte[1]).kind())
        .isEqualTo(Protocol.BAD_REQUEST);
    // an offset past the end of the body
    final byte[] badOffset = Messages.encodeEvidenceRequest(new byte[4]);
    ByteBuffer.wrap(badOffset).order(ByteOrder.LITTLE_ENDIAN).putInt(0, 9);
    assertThat(exchange(connection, 5, Protocol.GET_EVIDENCE, badOffset).kind())
        .isEqualTo(Protocol.BAD_REQUEST);
    assertThat(exchange(connection, 6, Protocol.STATUS, Messages.encodeStatusRequest()).kind())
        .isEqualTo(Protocol.OK);
  }

  @Test
  void impossibleBodySizeClosesTheConnectionWithoutAReply() throws IOException {
    startServer();
    for (final long size : new long[] {Protocol.MAX_BODY_SIZE + 1L, 0xFFFF_FFFFL}) {
      final Connection connection = connect();
      final byte[] header =
          ByteBuffer.allocate(Frames.HEADER_SIZE + 1)
              .order(ByteOrder.LITTLE_ENDIAN)
              .putInt(0, (int) size)
              .put(8, (byte) Protocol.STATUS)
              .array();
      send(connection, header);
      assertThat(readOrEnd(connection)).isEqualTo(-1);
    }
  }
}
