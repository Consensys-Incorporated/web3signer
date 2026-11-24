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
import tech.pegasys.teku.bls.BLSSecretKey;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.SecureRandom;
import java.util.HexFormat;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class BlstTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final HexFormat HEX = HexFormat.of();
  private final Blst blst = new Blst(BlstTestLibrary.path());

  private byte[] publicKey(final Arena arena, final Blst.Scratch scratch, final byte[] secret) {
    final MemorySegment scalar = Blst.allocateScalar(arena);
    blst.scalarFromBigEndian(scratch, secret, 0, scalar);
    assertThat(blst.isValidSecretKey(scalar)).isTrue();
    final byte[] publicKey = new byte[48];
    blst.publicKey(scratch, scalar, publicKey, 0);
    return publicKey;
  }

  @Test
  void knownAnswer() {
    try (Arena arena = Arena.ofConfined()) {
      final byte[] publicKey =
          publicKey(
              arena,
              new Blst.Scratch(arena),
              HEX.parseHex("25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"));
      assertThat(HEX.formatHex(publicKey))
          .isEqualTo(
              "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c");
    }
  }

  @Test
  void matchesTekuForRandomKeysAndSigningRoots() {
    try (Arena arena = Arena.ofConfined()) {
      final Blst.Scratch scratch = new Blst.Scratch(arena);
      for (int i = 0; i < 200; i++) {
        final BLSKeyPair keyPair = BLSKeyPair.random(RANDOM);
        final byte[] secret = keyPair.getSecretKey().toBytes().toArrayUnsafe();
        final byte[] message = new byte[32];
        RANDOM.nextBytes(message);

        final MemorySegment scalar = Blst.allocateScalar(arena);
        blst.scalarFromBigEndian(scratch, secret, 0, scalar);
        final byte[] publicKey = new byte[48];
        blst.publicKey(scratch, scalar, publicKey, 0);
        final byte[] signature = new byte[96];
        blst.sign(scratch, scalar, message, 0, signature, 0);

        assertThat(publicKey).isEqualTo(keyPair.getPublicKey().toBytesCompressed().toArrayUnsafe());
        assertThat(signature)
            .isEqualTo(
                BLS.sign(keyPair.getSecretKey(), Bytes.wrap(message))
                    .toBytesCompressed()
                    .toArrayUnsafe());
      }
    }
  }

  @Test
  void signsAtAnOffsetInsideABuffer() {
    final BLSSecretKey secretKey =
        BLSSecretKey.fromBytes(
            org.apache.tuweni.bytes.Bytes32.fromHexString(
                "25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"));
    final byte[] buffer = new byte[100];
    RANDOM.nextBytes(buffer);
    try (Arena arena = Arena.ofConfined()) {
      final Blst.Scratch scratch = new Blst.Scratch(arena);
      final MemorySegment scalar = Blst.allocateScalar(arena);
      blst.scalarFromBigEndian(scratch, secretKey.toBytes().toArrayUnsafe(), 0, scalar);
      final byte[] out = new byte[110];
      blst.sign(scratch, scalar, buffer, 10, out, 7);
      final Bytes expected = BLS.sign(secretKey, Bytes.wrap(buffer, 10, 32)).toBytesCompressed();
      assertThat(Bytes.wrap(out, 7, 96)).isEqualTo(expected);
    }
  }

  @Test
  void zeroAndGroupOrderAreNotValidSecrets() {
    try (Arena arena = Arena.ofConfined()) {
      final Blst.Scratch scratch = new Blst.Scratch(arena);
      final MemorySegment scalar = Blst.allocateScalar(arena);
      blst.scalarFromBigEndian(scratch, new byte[32], 0, scalar);
      assertThat(blst.isValidSecretKey(scalar)).isFalse();
      blst.scalarFromBigEndian(
          scratch,
          HEX.parseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
          0,
          scalar);
      assertThat(blst.isValidSecretKey(scalar)).isFalse();
      blst.scalarFromBigEndian(
          scratch,
          HEX.parseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
          0,
          scalar);
      assertThat(blst.isValidSecretKey(scalar)).isTrue();
    }
  }
}
