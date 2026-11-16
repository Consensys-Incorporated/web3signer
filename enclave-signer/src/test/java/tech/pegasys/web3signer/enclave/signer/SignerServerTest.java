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
import tech.pegasys.web3signer.enclave.protocol.Connection;
import tech.pegasys.web3signer.enclave.protocol.EnclaveAddress;
import tech.pegasys.web3signer.enclave.protocol.EnclaveClient;
import tech.pegasys.web3signer.enclave.protocol.EnclaveException;
import tech.pegasys.web3signer.enclave.protocol.EnclaveStatus;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Listener;
import tech.pegasys.web3signer.enclave.protocol.Payloads;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.protocol.Transports;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SignerServerTest {
  private static final Blst BLST = new Blst(BlstTestLibrary.path());

  /** Number of response frames in each write of the server. */
  private final List<Integer> framesPerWrite = new CopyOnWriteArrayList<>();

  private final List<AutoCloseable> resources = new ArrayList<>();
  private SignerServer server;

  @AfterEach
  void tearDown() throws Exception {
    for (final AutoCloseable resource : resources.reversed()) {
      resource.close();
    }
  }

  private SignerServer startServer() throws IOException {
    final Listener tcp = Transports.listen(EnclaveAddress.parseListen("tcp:127.0.0.1:0"));
    server =
        new SignerServer(
            new CountingListener(tcp), BLST, new DevAttestor(), Protocol.PLATFORM_DEV, 64, "test");
    server.start();
    resources.add(server);
    return server;
  }

  private EnclaveClient client() {
    final EnclaveClient client =
        EnclaveClient.create(server.address(), new EnclaveClient.Options(1, 8, 5000));
    resources.add(client);
    return client;
  }

  private Connection connect() throws IOException {
    final Connection connection = Transports.connect(server.address(), 5000);
    resources.add(connection);
    return connection;
  }

  private static void send(final Connection connection, final byte[] bytes) throws IOException {
    connection.write(bytes, 0, bytes.length);
  }

  @Test
  void statusReportsThePlatformAndKeyCount() throws IOException {
    startServer();
    TestKeys.load(server.keys(), BLST, TestKeys.random(2));
    final EnclaveStatus status = client().status();
    assertThat(status.protocolVersion()).isEqualTo(1);
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
      final byte[] signature =
          client.sign(key.getPublicKey().toBytesCompressed().toArrayUnsafe(), root.toArrayUnsafe());
      final BLSSignature blsSignature = BLSSignature.fromBytesCompressed(Bytes.wrap(signature));
      assertThat(BLS.verify(key.getPublicKey(), root, blsSignature)).isTrue();
      assertThat(blsSignature).isEqualTo(BLS.sign(key.getSecretKey(), root));
    }
    final byte[] json =
        "{\"type\":\"json payload\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final byte[] signature =
        client.sign(keys.get(0).getPublicKey().toBytesCompressed().toArrayUnsafe(), json);
    assertThat(Bytes.wrap(signature))
        .isEqualTo(BLS.sign(keys.get(0).getSecretKey(), Bytes.wrap(json)).toBytesCompressed());
  }

  @Test
  void unknownKeyIsRefused() throws IOException {
    startServer();
    TestKeys.load(server.keys(), BLST, TestKeys.random(1));
    final byte[] other =
        TestKeys.random(1).get(0).getPublicKey().toBytesCompressed().toArrayUnsafe();
    assertThatThrownBy(() -> client().sign(other, new byte[32]))
        .isInstanceOfSatisfying(
            EnclaveException.class, e -> assertThat(e.status()).isEqualTo(Protocol.UNKNOWN_KEY));
  }

  @Test
  void publicKeyPagesAreCompleteAndOrdered() throws IOException {
    startServer();
    final int count = 20_000;
    final byte[] keys = new byte[count * 48];
    new Random(1).nextBytes(keys);
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment scalars = arena.allocate(count * 32L, 8);
      assertThat(server.keys().addAll(keys, scalars, count)).isEqualTo(count);
    }
    final List<byte[]> listed = client().publicKeys();
    assertThat(listed).hasSize(count);
    for (int i = 0; i < count; i++) {
      assertThat(listed.get(i)).isEqualTo(java.util.Arrays.copyOfRange(keys, i * 48, i * 48 + 48));
    }

    final Connection connection = connect();
    send(
        connection,
        Frames.encode(Protocol.GET_PUBLIC_KEYS, 1, Payloads.getPublicKeysRequest(19_998, 5)));
    final Payloads.PublicKeysPage tail =
        Payloads.decodePublicKeys(Frames.read(connection).payload());
    assertThat(tail.total()).isEqualTo(count);
    assertThat(tail.publicKeys()).hasSize(2);
    final byte[] badLimit = new byte[8];
    send(connection, Frames.encode(Protocol.GET_PUBLIC_KEYS, 2, badLimit));
    assertThat(Frames.read(connection).status()).isEqualTo(Protocol.BAD_REQUEST);
  }

  @Test
  void connectionAboveTheMaximumIsRefused() throws IOException {
    startServer();
    for (int i = 0; i < 64; i++) {
      final Connection connection = connect();
      send(connection, Frames.encode(Protocol.STATUS, i, new byte[0]));
      assertThat(Frames.read(connection).status()).isEqualTo(Protocol.OK);
    }
    final Connection extra = connect();
    send(extra, Frames.encode(Protocol.STATUS, 65, new byte[0]));
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
  void eightSignFramesInOneWriteComeBackInOneWrite() throws IOException {
    startServer();
    final List<BLSKeyPair> keys = TestKeys.random(8);
    TestKeys.load(server.keys(), BLST, keys);
    final byte[] batch = new byte[8 * 91];
    final Bytes root = Bytes.random(32);
    for (int i = 0; i < 8; i++) {
      final byte[] frame =
          Frames.encode(
              Protocol.SIGN,
              100 + i,
              Payloads.signRequest(
                  keys.get(i).getPublicKey().toBytesCompressed().toArrayUnsafe(),
                  root.toArrayUnsafe()));
      System.arraycopy(frame, 0, batch, i * 91, 91);
    }
    final Connection connection = connect();
    send(connection, batch);
    for (int i = 0; i < 8; i++) {
      final Frame response = Frames.read(connection);
      assertThat(response.requestId()).isEqualTo(100 + i);
      assertThat(response.type()).isEqualTo(Protocol.SIGN | 0x80);
      assertThat(Bytes.wrap(Payloads.decodeSignature(response.payload())))
          .isEqualTo(BLS.sign(keys.get(i).getSecretKey(), root).toBytesCompressed());
    }
    assertThat(framesPerWrite).containsExactly(8);
  }

  @Test
  void malformedSignPayloadIsABadRequest() throws IOException {
    startServer();
    final Connection connection = connect();
    send(connection, Frames.encode(Protocol.SIGN, 1, new byte[49]));
    final Frame response = Frames.read(connection);
    assertThat(response.requestId()).isEqualTo(1);
    assertThat(response.payload()).containsExactly(Protocol.BAD_REQUEST);

    final byte[] wrongLength = Payloads.signRequest(new byte[48], new byte[32]);
    wrongLength[49] = 31;
    send(connection, Frames.encode(Protocol.SIGN, 2, wrongLength));
    assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);

    send(connection, Frames.encode(0x7f, 3, new byte[0]));
    assertThat(Frames.read(connection).payload()).containsExactly(Protocol.UNSUPPORTED);
    send(connection, Frames.encode(Protocol.STATUS, 4, new byte[1]));
    assertThat(Frames.read(connection).payload()).containsExactly(Protocol.BAD_REQUEST);
  }

  @Test
  void impossibleLengthClosesTheConnectionWithoutAReply() throws IOException {
    startServer();
    for (final String length : new String[] {"00000004", "00100001"}) {
      final Connection connection = connect();
      send(connection, HexFormat.of().parseHex(length + "01000000010000000000"));
      assertThat(readOrEnd(connection)).isEqualTo(-1);
    }
    assertThat(framesPerWrite).isEmpty();
  }

  /** Wraps accepted connections to count the response frames in each write. */
  private final class CountingListener implements Listener {
    private final Listener delegate;

    CountingListener(final Listener delegate) {
      this.delegate = delegate;
    }

    @Override
    public Connection accept() throws IOException {
      final Connection connection = delegate.accept();
      return new Connection() {
        @Override
        public int read(final byte[] buffer, final int offset, final int length)
            throws IOException {
          return connection.read(buffer, offset, length);
        }

        @Override
        public void write(final byte[] buffer, final int offset, final int length)
            throws IOException {
          int frames = 0;
          for (int at = offset; at < offset + length; at += 4 + Frames.getInt(buffer, at)) {
            frames++;
          }
          framesPerWrite.add(frames);
          connection.write(buffer, offset, length);
        }

        @Override
        public void close() {
          connection.close();
        }
      };
    }

    @Override
    public EnclaveAddress address() {
      return delegate.address();
    }

    @Override
    public void close() {
      delegate.close();
    }
  }
}
