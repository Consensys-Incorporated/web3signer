/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.dsl.utils;

import tech.pegasys.web3signer.core.service.http.ArtifactType;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.AggregateAndProofV2;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.AggregationSlot;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.BlockRequest;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.DepositMessage;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.Eth2SigningRequestBody;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.ForkInfo;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.RandaoReveal;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.SyncAggregatorSelectionData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.SyncCommitteeMessage;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.ValidatorRegistration;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.VersionedRequest;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.AttestationData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.BeaconBlock;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.VoluntaryExit;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.altair.ContributionAndProof;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.BuilderRequestAuth;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ExecutionPayloadBid;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ExecutionPayloadEnvelope;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.PayloadAttestationData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ProposerPreferences;

import org.apache.tuweni.bytes.Bytes;

public final class Eth2SigningRequestBodyBuilder {
  private ArtifactType type;
  private Bytes signingRoot;
  private ForkInfo forkInfo;
  private BeaconBlock block;
  private BlockRequest blockRequest;
  private AttestationData attestation;
  private AggregationSlot aggregationSlot;
  private AggregateAndProofV2 aggregateAndProofV2;
  private VoluntaryExit voluntaryExit;
  private RandaoReveal randaoReveal;
  private DepositMessage deposit;
  private SyncCommitteeMessage syncCommitteeMessage;
  private SyncAggregatorSelectionData syncAggregatorSelectionData;
  private ContributionAndProof contributionAndProof;
  private ValidatorRegistration validatorRegistration;
  private VersionedRequest<ExecutionPayloadBid> executionPayloadBid;
  private VersionedRequest<ExecutionPayloadEnvelope> executionPayloadEnvelope;
  private VersionedRequest<PayloadAttestationData> payloadAttestationMessage;
  private VersionedRequest<ProposerPreferences> proposerPreferences;
  private VersionedRequest<BuilderRequestAuth> builderRequestAuth;

  private Eth2SigningRequestBodyBuilder() {}

  public static Eth2SigningRequestBodyBuilder anEth2SigningRequestBody() {
    return new Eth2SigningRequestBodyBuilder();
  }

  public Eth2SigningRequestBodyBuilder withType(ArtifactType type) {
    this.type = type;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withSigningRoot(Bytes signingRoot) {
    this.signingRoot = signingRoot;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withForkInfo(ForkInfo forkInfo) {
    this.forkInfo = forkInfo;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withBlock(BeaconBlock block) {
    this.block = block;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withBlockRequest(BlockRequest blockRequest) {
    this.blockRequest = blockRequest;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withAttestation(AttestationData attestation) {
    this.attestation = attestation;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withAggregationSlot(AggregationSlot aggregationSlot) {
    this.aggregationSlot = aggregationSlot;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withAggregateAndProofV2(
      AggregateAndProofV2 aggregateAndProofV2) {
    this.aggregateAndProofV2 = aggregateAndProofV2;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withVoluntaryExit(VoluntaryExit voluntaryExit) {
    this.voluntaryExit = voluntaryExit;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withRandaoReveal(RandaoReveal randaoReveal) {
    this.randaoReveal = randaoReveal;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withDeposit(DepositMessage deposit) {
    this.deposit = deposit;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withSyncCommitteeMessage(
      SyncCommitteeMessage syncCommitteeMessage) {
    this.syncCommitteeMessage = syncCommitteeMessage;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withSyncAggregatorSelectionData(
      SyncAggregatorSelectionData syncAggregatorSelectionData) {
    this.syncAggregatorSelectionData = syncAggregatorSelectionData;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withContributionAndProof(
      ContributionAndProof contributionAndProof) {
    this.contributionAndProof = contributionAndProof;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withValidatorRegistration(
      ValidatorRegistration validatorRegistration) {
    this.validatorRegistration = validatorRegistration;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withExecutionPayloadBid(
      VersionedRequest<ExecutionPayloadBid> executionPayloadBid) {
    this.executionPayloadBid = executionPayloadBid;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withExecutionPayloadEnvelope(
      VersionedRequest<ExecutionPayloadEnvelope> executionPayloadEnvelope) {
    this.executionPayloadEnvelope = executionPayloadEnvelope;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withPayloadAttestationMessage(
      VersionedRequest<PayloadAttestationData> payloadAttestationMessage) {
    this.payloadAttestationMessage = payloadAttestationMessage;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withProposerPreferences(
      VersionedRequest<ProposerPreferences> proposerPreferences) {
    this.proposerPreferences = proposerPreferences;
    return this;
  }

  public Eth2SigningRequestBodyBuilder withBuilderRequestAuth(
      VersionedRequest<BuilderRequestAuth> builderRequestAuth) {
    this.builderRequestAuth = builderRequestAuth;
    return this;
  }

  public Eth2SigningRequestBody build() {
    return new Eth2SigningRequestBody(
        type,
        signingRoot,
        forkInfo,
        block,
        blockRequest,
        attestation,
        aggregationSlot,
        aggregateAndProofV2,
        voluntaryExit,
        randaoReveal,
        deposit,
        syncCommitteeMessage,
        syncAggregatorSelectionData,
        contributionAndProof,
        validatorRegistration,
        executionPayloadBid,
        executionPayloadEnvelope,
        payloadAttestationMessage,
        proposerPreferences,
        builderRequestAuth);
  }
}
