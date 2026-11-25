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
package tech.pegasys.web3signer.enclave.protocol;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.teku.infrastructure.ssz.SszContainer;
import tech.pegasys.teku.infrastructure.ssz.SszData;
import tech.pegasys.teku.infrastructure.ssz.impl.SszContainerImpl;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszByte;
import tech.pegasys.teku.infrastructure.ssz.schema.SszContainerSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.SszListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.SszPrimitiveSchemas;
import tech.pegasys.teku.infrastructure.ssz.schema.SszSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszByteListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszByteVectorSchema;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.KeyLoadCounts;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/**
 * Every message encoded by {@link Messages} equals Teku's SSZ encoding of the same container, and
 * decodes back to the same values.
 */
class TekuSszCompatibilityTest {
  private final Random random = new Random(42);

  private byte[] randomBytes(final int size) {
    final byte[] bytes = new byte[size];
    random.nextBytes(bytes);
    return bytes;
  }

  private static SszContainerSchema<SszContainer> container(final SszSchema<?>... fields) {
    return SszContainerSchema.create(List.of(fields), SszContainerImpl::new);
  }

  private static SszData uint8(final int value) {
    return SszByte.asUInt8((byte) value);
  }

  // Teku has no uint16 or uint32 schema: a little-endian byte vector encodes the same
  private static final SszByteVectorSchema<?> UINT16 = SszByteVectorSchema.create(2);
  private static final SszByteVectorSchema<?> UINT32 = SszByteVectorSchema.create(4);

  private static SszData uint16(final int value) {
    return vector(
        ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) value).array());
  }

  private static SszData uint32(final long value) {
    return vector(
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) value).array());
  }

  private static SszData vector(final byte[] value) {
    return SszByteVectorSchema.create(value.length).fromBytes(Bytes.wrap(value));
  }

  private static SszData list(final int max, final byte[] value) {
    return SszByteListSchema.create(max).fromBytes(Bytes.wrap(value));
  }

  /** Asserts that both encodings agree and that Teku decodes ours. */
  private static void assertSameEncoding(
      final byte[] ours, final SszContainerSchema<SszContainer> schema, final SszData... fields) {
    final Bytes teku = schema.createFromFieldValues(List.of(fields)).sszSerialize();
    assertThat(HexFormat.of().formatHex(ours)).isEqualTo(teku.toUnprefixedHexString());
    assertThat(schema.sszDeserialize(Bytes.wrap(ours)).sszSerialize()).isEqualTo(teku);
  }

  /** Asserts that a whole-body list encodes as Teku's list, and that Teku decodes ours. */
  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void assertSameListEncoding(
      final byte[] ours, final SszListSchema schema, final List<SszData> elements) {
    final Bytes teku = schema.createFromElements(elements).sszSerialize();
    assertThat(HexFormat.of().formatHex(ours)).isEqualTo(teku.toUnprefixedHexString());
    assertThat(schema.sszDeserialize(Bytes.wrap(ours)).sszSerialize()).isEqualTo(teku);
  }

  @Test
  void status() throws Exception {
    final byte[] bootId = randomBytes(16);
    final byte[] ours =
        Messages.encodeStatus(Protocol.PLATFORM_AWS_NITRO, 4, 1000, bootId, "26.11.1");
    assertSameEncoding(
        ours,
        container(
            SszPrimitiveSchemas.UINT8_SCHEMA,
            SszPrimitiveSchemas.UINT8_SCHEMA,
            UINT16,
            UINT32,
            SszByteVectorSchema.create(16),
            SszByteListSchema.create(256)),
        uint8(Protocol.VERSION),
        uint8(Protocol.PLATFORM_AWS_NITRO),
        uint16(4),
        uint32(1000),
        vector(bootId),
        list(256, "26.11.1".getBytes(US_ASCII)));
    assertThat(Messages.decodeStatus(ours))
        .isEqualTo(
            new Messages.Status(
                Protocol.VERSION,
                Protocol.PLATFORM_AWS_NITRO,
                4,
                1000,
                HexFormat.of().formatHex(bootId),
                "26.11.1"));
  }

  @Test
  void pageRequest() throws Exception {
    // above 2^31: the top bit of the uint32 counts
    final long offset = 4_000_000_000L;
    final byte[] ours =
        Messages.encodePublicKeysRequest(new Messages.PublicKeysRequest(offset, 16_384));
    assertSameEncoding(ours, container(UINT32, UINT32), uint32(offset), uint32(16_384));
    assertThat(Messages.decodePublicKeysRequest(ours))
        .isEqualTo(new Messages.PublicKeysRequest(offset, 16_384));
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private void assertPublicKeysPage(final int count) throws Exception {
    final List<byte[]> keys = new ArrayList<>();
    final SszByteVectorSchema<?> key = SszByteVectorSchema.create(48);
    final List<SszData> elements = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      final byte[] publicKey = randomBytes(48);
      keys.add(publicKey);
      elements.add(key.fromBytes(Bytes.wrap(publicKey)));
    }
    final byte[] ours = Messages.encodePublicKeys(keys);
    final SszListSchema listSchema = SszListSchema.create(key, Protocol.MAX_PUBLIC_KEYS_PAGE);
    assertSameListEncoding(ours, listSchema, elements);
    assertThat(Messages.decodePublicKeys(ours)).containsExactlyElementsOf(keys);
  }

  @Test
  void publicKeys() throws Exception {
    assertPublicKeysPage(3);
  }

  @Test
  void emptyPublicKeysPage() throws Exception {
    assertPublicKeysPage(0);
  }

  @Test
  void signRequestAndResponse() throws Exception {
    final byte[] publicKey = randomBytes(48);
    final byte[] signingRoot = randomBytes(32);
    final byte[] ours =
        Messages.encodeSignRequest(new Messages.SignRequest(publicKey, signingRoot));
    assertSameEncoding(
        ours,
        container(SszByteVectorSchema.create(48), SszByteVectorSchema.create(32)),
        vector(publicKey),
        vector(signingRoot));
    final Messages.SignRequest decoded = Messages.decodeSignRequest(ours);
    assertThat(decoded.pubKey()).isEqualTo(publicKey);
    assertThat(decoded.signingRoot()).isEqualTo(signingRoot);

    final byte[] signature = randomBytes(96);
    assertSameEncoding(
        Messages.encodeSignature(signature),
        container(SszByteVectorSchema.create(96)),
        vector(signature));
    assertThat(Messages.decodeSignature(Messages.encodeSignature(signature))).isEqualTo(signature);
  }

  @Test
  void evidenceRequestAndResponse() throws Exception {
    final byte[] nonce = randomBytes(32);
    final byte[] request = Messages.encodeNonce(nonce);
    assertThat(request).isEqualTo(list(64, nonce).sszSerialize().toArrayUnsafe());
    assertThat(Messages.decodeNonce(request)).isEqualTo(nonce);

    final byte[] releaseKey = randomBytes(294);
    final byte[] evidence = randomBytes(4500);
    final byte[] ours =
        Messages.encodeEvidence(new Evidence(Protocol.EVIDENCE_AWS_NITRO, releaseKey, evidence));
    assertSameEncoding(
        ours,
        container(
            SszPrimitiveSchemas.UINT8_SCHEMA,
            SszByteListSchema.create(Protocol.MAX_RELEASE_KEY_SIZE),
            SszByteListSchema.create(Protocol.MAX_EVIDENCE_SIZE)),
        uint8(Protocol.EVIDENCE_AWS_NITRO),
        list(Protocol.MAX_RELEASE_KEY_SIZE, releaseKey),
        list(Protocol.MAX_EVIDENCE_SIZE, evidence));
    final Evidence decoded = Messages.decodeEvidence(ours);
    assertThat(decoded.evidenceType()).isEqualTo(Protocol.EVIDENCE_AWS_NITRO);
    assertThat(decoded.releaseKey()).isEqualTo(releaseKey);
    assertThat(decoded.evidence()).isEqualTo(evidence);
  }

  @Test
  void unwrapDekRequest() throws Exception {
    final byte[] blob = randomBytes(700);
    final byte[] ours =
        Messages.encodeUnwrapDekRequest(
            new Messages.UnwrapDekRequest(Protocol.BLOB_FORMAT_CMS, blob));
    assertSameEncoding(
        ours,
        container(
            SszPrimitiveSchemas.UINT8_SCHEMA, SszByteListSchema.create(Protocol.MAX_BLOB_SIZE)),
        uint8(Protocol.BLOB_FORMAT_CMS),
        list(Protocol.MAX_BLOB_SIZE, blob));
    final Messages.UnwrapDekRequest decoded = Messages.decodeUnwrapDekRequest(ours);
    assertThat(decoded.format()).isEqualTo(Protocol.BLOB_FORMAT_CMS);
    assertThat(decoded.blob()).isEqualTo(blob);
  }

  @Test
  @SuppressWarnings({"unchecked", "rawtypes"})
  void loadKeysRequestAndResponse() throws Exception {
    final SszContainerSchema<SszContainer> entry =
        container(
            SszByteVectorSchema.create(48),
            SszByteVectorSchema.create(12),
            SszByteVectorSchema.create(48));
    final SszListSchema listSchema = SszListSchema.create(entry, Protocol.MAX_LOAD_KEYS);
    final List<SealedKey> keys = new ArrayList<>();
    final List<SszData> elements = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      final SealedKey key = new SealedKey(randomBytes(48), randomBytes(12), randomBytes(48));
      keys.add(key);
      elements.add(
          entry.createFromFieldValues(
              List.of(vector(key.pubKey()), vector(key.nonce()), vector(key.ciphertext()))));
    }
    final byte[] ours = Messages.encodeSealedKeys(keys);
    assertSameListEncoding(ours, listSchema, elements);
    assertThat(Messages.decodeSealedKeys(ours))
        .usingRecursiveFieldByFieldElementComparator()
        .isEqualTo(keys);

    final KeyLoadCounts result = new KeyLoadCounts(5, 2, 1);
    final byte[] response = Messages.encodeKeyLoadCounts(result);
    assertSameEncoding(
        response, container(UINT32, UINT32, UINT32), uint32(5), uint32(2), uint32(1));
    assertThat(Messages.decodeKeyLoadCounts(response)).isEqualTo(result);
  }

  @Test
  void errorMessage() throws Exception {
    final byte[] ours = Messages.encodeErrorMessage("release blob did not open");
    assertThat(ours)
        .isEqualTo(
            SszByteListSchema.create(256)
                .fromBytes(Bytes.wrap("release blob did not open".getBytes(US_ASCII)))
                .sszSerialize()
                .toArrayUnsafe());
    assertThat(Messages.decodeErrorMessage(ours)).isEqualTo("release blob did not open");
  }
}
