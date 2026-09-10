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
package tech.pegasys.web3signer.core.service.http.handlers.signing.eth2;

import tech.pegasys.web3signer.core.service.http.ArtifactType;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.AttestationData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.BeaconBlock;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.VoluntaryExit;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.altair.ContributionAndProof;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.BuilderRequestAuth;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ExecutionPayloadBid;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ExecutionPayloadEnvelope;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.PayloadAttestationData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ProposerPreferences;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes;

public record Eth2SigningRequestBody(
    @JsonProperty(value = "type", required = true) ArtifactType type,
    @JsonProperty("signing_root") @JsonAlias("signingRoot") Bytes signingRoot,
    @JsonProperty("fork_info") ForkInfo forkInfo,
    @JsonProperty("block") BeaconBlock block,
    @JsonProperty("beacon_block") BlockRequest blockRequest,
    @JsonProperty("attestation") AttestationData attestation,
    @JsonProperty("aggregation_slot") AggregationSlot aggregationSlot,
    @JsonProperty("aggregate_and_proof") AggregateAndProofV2 aggregateAndProofV2,
    @JsonProperty("voluntary_exit") VoluntaryExit voluntaryExit,
    @JsonProperty("randao_reveal") RandaoReveal randaoReveal,
    @JsonProperty("deposit") DepositMessage deposit,
    @JsonProperty("sync_committee_message") SyncCommitteeMessage syncCommitteeMessage,
    @JsonProperty("sync_aggregator_selection_data")
        SyncAggregatorSelectionData syncAggregatorSelectionData,
    @JsonProperty("contribution_and_proof") ContributionAndProof contributionAndProof,
    @JsonProperty("validator_registration") ValidatorRegistration validatorRegistration,
    @JsonProperty("execution_payload_bid")
        VersionedRequest<ExecutionPayloadBid> executionPayloadBid,
    @JsonProperty("execution_payload_envelope")
        VersionedRequest<ExecutionPayloadEnvelope> executionPayloadEnvelope,
    @JsonProperty("payload_attestation_message")
        VersionedRequest<PayloadAttestationData> payloadAttestationMessage,
    @JsonProperty("proposer_preferences") VersionedRequest<ProposerPreferences> proposerPreferences,
    @JsonProperty("builder_request_auth")
        VersionedRequest<BuilderRequestAuth> builderRequestAuth) {}
