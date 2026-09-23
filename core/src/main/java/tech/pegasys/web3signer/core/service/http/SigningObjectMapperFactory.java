/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.http;

import tech.pegasys.teku.infrastructure.bytes.Bytes20;
import tech.pegasys.teku.infrastructure.bytes.Bytes4;
import tech.pegasys.teku.infrastructure.ssz.collections.SszBitvector;
import tech.pegasys.web3signer.common.JacksonSerializers.HexDeserialiser;
import tech.pegasys.web3signer.common.JacksonSerializers.HexSerialiser;
import tech.pegasys.web3signer.common.JacksonSerializers.StringUInt64Deserializer;
import tech.pegasys.web3signer.common.JacksonSerializers.StringUInt64Serialiser;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.BlockRequest;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.json.BlockRequestDeserializer;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.BLSPubKey;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.BLSSignature;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.KZGCommitment;
import tech.pegasys.web3signer.core.service.http.serializers.BLSPubKeyDeserializer;
import tech.pegasys.web3signer.core.service.http.serializers.BLSPubKeySerializer;
import tech.pegasys.web3signer.core.service.http.serializers.BLSSignatureDeserializer;
import tech.pegasys.web3signer.core.service.http.serializers.BLSSignatureSerializer;
import tech.pegasys.web3signer.core.service.http.serializers.KZGCommitmentDeserializer;
import tech.pegasys.web3signer.core.service.http.serializers.KZGCommitmentSerializer;
import tech.pegasys.web3signer.core.service.http.serializers.SszBitvectorSerializer;
import tech.pegasys.web3signer.core.service.http.serializers.UInt256Deserializer;
import tech.pegasys.web3signer.core.service.http.serializers.UInt256Serializer;
import tech.pegasys.web3signer.signing.config.metadata.parser.SigningMetadataModule;
import tech.pegasys.web3signer.signing.config.metadata.parser.SigningMetadataModule.Bytes32Serializer;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.apache.tuweni.units.bigints.UInt64;

public class SigningObjectMapperFactory {
  private final ObjectMapper objectMapper;

  private static final SigningObjectMapperFactory FACTORY = new SigningObjectMapperFactory();

  private SigningObjectMapperFactory() {
    this.objectMapper =
        JsonMapper.builder()
            .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .addModule(web3SignerMappers())
            .build();
  }

  private Module web3SignerMappers() {
    final SimpleModule module =
        new SimpleModule("SigningJsonRpcModule", new Version(1, 0, 0, null, null, null));
    module.addDeserializer(Bytes.class, new HexDeserialiser());
    module.addSerializer(Bytes.class, new HexSerialiser());
    module.addDeserializer(UInt64.class, new StringUInt64Deserializer());
    module.addSerializer(UInt64.class, new StringUInt64Serialiser());
    module.addDeserializer(
        tech.pegasys.teku.infrastructure.unsigned.UInt64.class,
        new SigningMetadataModule.TekuUInt64Deserializer());
    module.addSerializer(
        tech.pegasys.teku.infrastructure.unsigned.UInt64.class,
        new SigningMetadataModule.TekuUInt64Serializer());

    module.addSerializer(Bytes32.class, new Bytes32Serializer());
    module.addDeserializer(Bytes32.class, new SigningMetadataModule.Bytes32Deserializer());
    module.addDeserializer(Bytes4.class, new SigningMetadataModule.Bytes4Deserializer());
    module.addSerializer(Bytes4.class, new SigningMetadataModule.Bytes4Serializer());
    module.addDeserializer(Bytes.class, new SigningMetadataModule.BytesDeserializer());
    module.addSerializer(Bytes.class, new SigningMetadataModule.BytesSerializer());
    module.addDeserializer(Double.class, new SigningMetadataModule.DoubleDeserializer());
    module.addSerializer(Double.class, new SigningMetadataModule.DoubleSerializer());

    module.addSerializer(BLSPubKey.class, new BLSPubKeySerializer());
    module.addDeserializer(BLSPubKey.class, new BLSPubKeyDeserializer());
    module.addDeserializer(BLSSignature.class, new BLSSignatureDeserializer());
    module.addSerializer(BLSSignature.class, new BLSSignatureSerializer());
    module.addSerializer(KZGCommitment.class, new KZGCommitmentSerializer());
    module.addDeserializer(KZGCommitment.class, new KZGCommitmentDeserializer());
    module.addSerializer(UInt256.class, new UInt256Serializer());
    module.addDeserializer(UInt256.class, new UInt256Deserializer());

    module.addSerializer(SszBitvector.class, new SszBitvectorSerializer());

    module.addDeserializer(BlockRequest.class, new BlockRequestDeserializer());

    module.addDeserializer(Bytes20.class, new SigningMetadataModule.Bytes20Deserializer());
    module.addSerializer(Bytes20.class, new SigningMetadataModule.Bytes20Serializer());

    module.addDeserializer(
        tech.pegasys.teku.bls.BLSPublicKey.class,
        new SigningMetadataModule.BLSPublicKeyDeserializer());
    module.addSerializer(
        tech.pegasys.teku.bls.BLSPublicKey.class,
        new SigningMetadataModule.BLSPublicKeySerializer());

    return module;
  }

  public static ObjectMapper createObjectMapper() {
    return FACTORY.objectMapper;
  }
}
