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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import tech.pegasys.teku.infrastructure.ssz.sos.SszDeserializeException;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.KeyLoadCounts;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.io.IOException;
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
 * decodes back to the same values. Teku's schemas take the README limits as literals, so that a
 * {@link Protocol} constant that drifts from the README fails the samples at and past the limit.
 */
class TekuSszCompatibilityTest {
  private static final int MAX_VERSION_SIZE = 256;
  private static final int MAX_ERROR_MESSAGE_SIZE = 256;
  private static final int MAX_NONCE_SIZE = 64;
  private static final int MAX_RELEASE_KEY_SIZE = 2048;
  private static final int MAX_EVIDENCE_SIZE = 65_536;
  private static final int MAX_BLOB_SIZE = 65_536;
  private static final int MAX_PUBLIC_KEYS_PAGE = 4096;
  private static final int MAX_LOAD_KEYS = 4096;

  private static final SszByteVectorSchema<?> PUBLIC_KEY = SszByteVectorSchema.create(48);
  private static final SszContainerSchema<SszContainer> SEALED_KEY =
      container(
          SszByteVectorSchema.create(48),
          SszByteVectorSchema.create(12),
          SszByteVectorSchema.create(48));

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

  /** Asserts that both encodings agree. */
  private static void assertSameEncoding(
      final byte[] ours, final SszContainerSchema<SszContainer> schema, final SszData... fields) {
    final Bytes teku = schema.createFromFieldValues(List.of(fields)).sszSerialize();
    assertThat(HexFormat.of().formatHex(ours)).isEqualTo(teku.toUnprefixedHexString());
  }

  /** Asserts that a whole-body list encodes as Teku's list. */
  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void assertSameListEncoding(
      final byte[] ours, final SszListSchema schema, final List<SszData> elements) {
    final Bytes teku = schema.createFromElements(elements).sszSerialize();
    assertThat(HexFormat.of().formatHex(ours)).isEqualTo(teku.toUnprefixedHexString());
  }

  // ------------------------------------------------------------------ schemas

  private static SszContainerSchema<SszContainer> statusSchema(final int maxVersionSize) {
    return container(
        SszPrimitiveSchemas.UINT8_SCHEMA,
        SszPrimitiveSchemas.UINT8_SCHEMA,
        UINT16,
        UINT32,
        SszByteVectorSchema.create(16),
        SszByteListSchema.create(maxVersionSize));
  }

  private static SszContainerSchema<SszContainer> evidenceSchema(
      final int maxReleaseKeySize, final int maxEvidenceSize) {
    return container(
        SszPrimitiveSchemas.UINT8_SCHEMA,
        SszByteListSchema.create(maxReleaseKeySize),
        SszByteListSchema.create(maxEvidenceSize));
  }

  private static SszContainerSchema<SszContainer> unwrapDekSchema(final int maxBlobSize) {
    return container(SszPrimitiveSchemas.UINT8_SCHEMA, SszByteListSchema.create(maxBlobSize));
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static SszListSchema publicKeysSchema(final int maxCount) {
    return SszListSchema.create(PUBLIC_KEY, maxCount);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static SszListSchema sealedKeysSchema(final int maxCount) {
    return SszListSchema.create(SEALED_KEY, maxCount);
  }

  // ------------------------------------------------------------------ messages

  @Test
  void status() throws Exception {
    assertStatus("26.11.1");
    assertStatus("");
    assertStatus("v".repeat(MAX_VERSION_SIZE));
  }

  private void assertStatus(final String version) throws Exception {
    final byte[] bootId = randomBytes(16);
    final byte[] ours =
        Messages.encodeStatus(Protocol.PLATFORM_AWS_NITRO, 4, 1000, bootId, version);
    assertSameEncoding(
        ours,
        statusSchema(MAX_VERSION_SIZE),
        uint8(Protocol.VERSION),
        uint8(Protocol.PLATFORM_AWS_NITRO),
        uint16(4),
        uint32(1000),
        vector(bootId),
        list(MAX_VERSION_SIZE, version.getBytes(US_ASCII)));
    assertThat(Messages.decodeStatus(ours))
        .isEqualTo(
            new Messages.Status(
                Protocol.VERSION,
                Protocol.PLATFORM_AWS_NITRO,
                4,
                1000,
                HexFormat.of().formatHex(bootId),
                version));
  }

  @Test
  void pageRequest() throws Exception {
    // above 2^31: the top bit of the uint32 counts
    final long offset = 4_000_000_000L;
    final byte[] ours =
        Messages.encodePublicKeysRequest(
            new Messages.PublicKeysRequest(offset, MAX_PUBLIC_KEYS_PAGE));
    assertSameEncoding(
        ours, container(UINT32, UINT32), uint32(offset), uint32(MAX_PUBLIC_KEYS_PAGE));
    assertThat(Messages.decodePublicKeysRequest(ours))
        .isEqualTo(new Messages.PublicKeysRequest(offset, MAX_PUBLIC_KEYS_PAGE));
  }

  @Test
  void publicKeys() throws Exception {
    assertPublicKeysPage(3);
    assertPublicKeysPage(0);
    assertPublicKeysPage(MAX_PUBLIC_KEYS_PAGE);
  }

  private void assertPublicKeysPage(final int count) throws Exception {
    final List<byte[]> keys = new ArrayList<>();
    final List<SszData> elements = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      final byte[] publicKey = randomBytes(48);
      keys.add(publicKey);
      elements.add(vector(publicKey));
    }
    final byte[] ours = Messages.encodePublicKeys(keys);
    assertSameListEncoding(ours, publicKeysSchema(MAX_PUBLIC_KEYS_PAGE), elements);
    assertThat(Messages.decodePublicKeys(ours)).containsExactlyElementsOf(keys);
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
  void nonce() throws Exception {
    for (final int size : new int[] {32, 0, MAX_NONCE_SIZE}) {
      final byte[] nonce = randomBytes(size);
      final byte[] request = Messages.encodeNonce(nonce);
      assertThat(request).isEqualTo(list(MAX_NONCE_SIZE, nonce).sszSerialize().toArrayUnsafe());
      assertThat(Messages.decodeNonce(request)).isEqualTo(nonce);
    }
  }

  @Test
  void evidence() throws Exception {
    assertEvidence(294, 4500);
    assertEvidence(0, 0);
    assertEvidence(MAX_RELEASE_KEY_SIZE, MAX_EVIDENCE_SIZE);
  }

  private void assertEvidence(final int releaseKeySize, final int evidenceSize) throws Exception {
    final byte[] releaseKey = randomBytes(releaseKeySize);
    final byte[] evidence = randomBytes(evidenceSize);
    final byte[] ours =
        Messages.encodeEvidence(new Evidence(Protocol.EVIDENCE_AWS_NITRO, releaseKey, evidence));
    assertSameEncoding(
        ours,
        evidenceSchema(MAX_RELEASE_KEY_SIZE, MAX_EVIDENCE_SIZE),
        uint8(Protocol.EVIDENCE_AWS_NITRO),
        list(MAX_RELEASE_KEY_SIZE, releaseKey),
        list(MAX_EVIDENCE_SIZE, evidence));
    final Evidence decoded = Messages.decodeEvidence(ours);
    assertThat(decoded.evidenceType()).isEqualTo(Protocol.EVIDENCE_AWS_NITRO);
    assertThat(decoded.releaseKey()).isEqualTo(releaseKey);
    assertThat(decoded.evidence()).isEqualTo(evidence);
  }

  @Test
  void unwrapDekRequest() throws Exception {
    for (final int size : new int[] {700, 0, MAX_BLOB_SIZE}) {
      final byte[] blob = randomBytes(size);
      final byte[] ours =
          Messages.encodeUnwrapDekRequest(
              new Messages.UnwrapDekRequest(Protocol.BLOB_FORMAT_CMS, blob));
      assertSameEncoding(
          ours,
          unwrapDekSchema(MAX_BLOB_SIZE),
          uint8(Protocol.BLOB_FORMAT_CMS),
          list(MAX_BLOB_SIZE, blob));
      final Messages.UnwrapDekRequest decoded = Messages.decodeUnwrapDekRequest(ours);
      assertThat(decoded.format()).isEqualTo(Protocol.BLOB_FORMAT_CMS);
      assertThat(decoded.blob()).isEqualTo(blob);
    }
  }

  @Test
  void loadKeysRequest() throws Exception {
    assertLoadKeys(3);
    assertLoadKeys(MAX_LOAD_KEYS);
  }

  private void assertLoadKeys(final int count) throws Exception {
    final List<SealedKey> keys = new ArrayList<>();
    final List<SszData> elements = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      final SealedKey key = new SealedKey(randomBytes(48), randomBytes(12), randomBytes(48));
      keys.add(key);
      elements.add(sealedKey(key));
    }
    final byte[] ours = Messages.encodeSealedKeys(keys);
    assertSameListEncoding(ours, sealedKeysSchema(MAX_LOAD_KEYS), elements);
    assertThat(Messages.decodeSealedKeys(ours))
        .usingRecursiveFieldByFieldElementComparator()
        .isEqualTo(keys);
  }

  private static SszData sealedKey(final SealedKey key) {
    return SEALED_KEY.createFromFieldValues(
        List.of(vector(key.pubKey()), vector(key.nonce()), vector(key.ciphertext())));
  }

  @Test
  void loadKeysResponse() throws Exception {
    final KeyLoadCounts result = new KeyLoadCounts(5, 2, 1);
    final byte[] response = Messages.encodeKeyLoadCounts(result);
    assertSameEncoding(
        response, container(UINT32, UINT32, UINT32), uint32(5), uint32(2), uint32(1));
    assertThat(Messages.decodeKeyLoadCounts(response, 8)).isEqualTo(result);
  }

  @Test
  void errorMessage() throws Exception {
    for (final String message :
        new String[] {"release blob did not open", "", "e".repeat(MAX_ERROR_MESSAGE_SIZE)}) {
      final byte[] ours = Messages.encodeErrorMessage(message);
      assertThat(ours)
          .isEqualTo(
              list(MAX_ERROR_MESSAGE_SIZE, message.getBytes(US_ASCII))
                  .sszSerialize()
                  .toArrayUnsafe());
      assertThat(Messages.decodeErrorMessage(ours)).isEqualTo(message);
    }
  }

  // ------------------------------------------------------------------ past the limit

  /** Bytes Teku's schema at the README limit refuses, and so must our decoder. */
  private static void assertBothRefuse(
      final Bytes body, final SszSchema<?> atLimit, final BodyCheck ours) {
    assertThatThrownBy(() -> atLimit.sszDeserialize(body))
        .isInstanceOf(SszDeserializeException.class);
    assertThatThrownBy(() -> ours.decode(body.toArrayUnsafe())).isInstanceOf(IOException.class);
  }

  @FunctionalInterface
  private interface BodyCheck {
    void decode(byte[] body) throws IOException;
  }

  @Test
  @SuppressWarnings("unchecked")
  void onePastTheLimitIsRefusedByBothSides() {
    final byte[] bootId = randomBytes(16);
    assertBothRefuse(
        statusSchema(MAX_VERSION_SIZE + 1)
            .createFromFieldValues(
                List.of(
                    uint8(Protocol.VERSION),
                    uint8(Protocol.PLATFORM_AWS_NITRO),
                    uint16(4),
                    uint32(1000),
                    vector(bootId),
                    list(MAX_VERSION_SIZE + 1, randomBytes(MAX_VERSION_SIZE + 1))))
            .sszSerialize(),
        statusSchema(MAX_VERSION_SIZE),
        Messages::decodeStatus);

    final byte[] nonce = randomBytes(MAX_NONCE_SIZE + 1);
    assertBothRefuse(
        list(MAX_NONCE_SIZE + 1, nonce).sszSerialize(),
        SszByteListSchema.create(MAX_NONCE_SIZE),
        Messages::decodeNonce);
    assertThatThrownBy(() -> Messages.encodeNonce(nonce))
        .isInstanceOf(IllegalArgumentException.class);

    final byte[] longReleaseKey = randomBytes(MAX_RELEASE_KEY_SIZE + 1);
    assertBothRefuse(
        evidenceSchema(MAX_RELEASE_KEY_SIZE + 1, MAX_EVIDENCE_SIZE)
            .createFromFieldValues(
                List.of(
                    uint8(Protocol.EVIDENCE_AWS_NITRO),
                    list(MAX_RELEASE_KEY_SIZE + 1, longReleaseKey),
                    list(MAX_EVIDENCE_SIZE, new byte[0])))
            .sszSerialize(),
        evidenceSchema(MAX_RELEASE_KEY_SIZE, MAX_EVIDENCE_SIZE),
        Messages::decodeEvidence);
    assertThatThrownBy(
            () ->
                Messages.encodeEvidence(
                    new Evidence(Protocol.EVIDENCE_AWS_NITRO, longReleaseKey, new byte[0])))
        .isInstanceOf(IllegalArgumentException.class);

    final byte[] longEvidence = randomBytes(MAX_EVIDENCE_SIZE + 1);
    assertBothRefuse(
        evidenceSchema(MAX_RELEASE_KEY_SIZE, MAX_EVIDENCE_SIZE + 1)
            .createFromFieldValues(
                List.of(
                    uint8(Protocol.EVIDENCE_AWS_NITRO),
                    list(MAX_RELEASE_KEY_SIZE, new byte[0]),
                    list(MAX_EVIDENCE_SIZE + 1, longEvidence)))
            .sszSerialize(),
        evidenceSchema(MAX_RELEASE_KEY_SIZE, MAX_EVIDENCE_SIZE),
        Messages::decodeEvidence);
    assertThatThrownBy(
            () ->
                Messages.encodeEvidence(
                    new Evidence(Protocol.EVIDENCE_AWS_NITRO, new byte[0], longEvidence)))
        .isInstanceOf(IllegalArgumentException.class);

    final byte[] longBlob = randomBytes(MAX_BLOB_SIZE + 1);
    assertBothRefuse(
        unwrapDekSchema(MAX_BLOB_SIZE + 1)
            .createFromFieldValues(
                List.of(uint8(Protocol.BLOB_FORMAT_CMS), list(MAX_BLOB_SIZE + 1, longBlob)))
            .sszSerialize(),
        unwrapDekSchema(MAX_BLOB_SIZE),
        Messages::decodeUnwrapDekRequest);
    assertThatThrownBy(
            () ->
                Messages.encodeUnwrapDekRequest(
                    new Messages.UnwrapDekRequest(Protocol.BLOB_FORMAT_CMS, longBlob)))
        .isInstanceOf(IllegalArgumentException.class);

    assertBothRefuse(
        list(MAX_ERROR_MESSAGE_SIZE + 1, randomBytes(MAX_ERROR_MESSAGE_SIZE + 1)).sszSerialize(),
        SszByteListSchema.create(MAX_ERROR_MESSAGE_SIZE),
        Messages::decodeErrorMessage);

    final List<byte[]> publicKeys = new ArrayList<>();
    final List<SszData> publicKeyElements = new ArrayList<>();
    for (int i = 0; i <= MAX_PUBLIC_KEYS_PAGE; i++) {
      publicKeys.add(randomBytes(48));
      publicKeyElements.add(vector(publicKeys.get(i)));
    }
    assertBothRefuse(
        publicKeysSchema(MAX_PUBLIC_KEYS_PAGE + 1)
            .createFromElements(publicKeyElements)
            .sszSerialize(),
        publicKeysSchema(MAX_PUBLIC_KEYS_PAGE),
        Messages::decodePublicKeys);
    assertThatThrownBy(() -> Messages.encodePublicKeys(publicKeys))
        .isInstanceOf(IllegalArgumentException.class);

    final List<SealedKey> sealedKeys = new ArrayList<>();
    final List<SszData> sealedKeyElements = new ArrayList<>();
    for (int i = 0; i <= MAX_LOAD_KEYS; i++) {
      sealedKeys.add(new SealedKey(randomBytes(48), randomBytes(12), randomBytes(48)));
      sealedKeyElements.add(sealedKey(sealedKeys.get(i)));
    }
    assertBothRefuse(
        sealedKeysSchema(MAX_LOAD_KEYS + 1).createFromElements(sealedKeyElements).sszSerialize(),
        sealedKeysSchema(MAX_LOAD_KEYS),
        Messages::decodeSealedKeys);
    assertThatThrownBy(() -> Messages.encodeSealedKeys(sealedKeys))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
