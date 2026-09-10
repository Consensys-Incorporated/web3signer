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

import static com.google.common.base.Preconditions.checkArgument;
import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.JSON_UTF_8;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.TEXT_PLAIN_UTF_8;
import static tech.pegasys.web3signer.core.util.DepositSigningRootUtil.computeDomain;
import static tech.pegasys.web3signer.signing.util.IdentifierUtils.normaliseIdentifier;

import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.SpecVersion;
import tech.pegasys.teku.spec.constants.Domain;
import tech.pegasys.teku.spec.datastructures.operations.versions.altair.SyncAggregatorSelectionDataSchema;
import tech.pegasys.teku.spec.logic.common.util.SyncCommitteeUtil;
import tech.pegasys.teku.spec.signatures.SigningRootUtil;
import tech.pegasys.web3signer.core.metrics.SlashingProtectionMetrics;
import tech.pegasys.web3signer.core.service.http.ArtifactType;
import tech.pegasys.web3signer.core.service.http.handlers.signing.SignerForIdentifier;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.AttestationData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.altair.ContributionAndProof;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.altair.SyncCommitteeContribution;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.BuilderRequestAuth;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ExecutionPayloadBid;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ExecutionPayloadEnvelope;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.PayloadAttestationData;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.gloas.ProposerPreferences;
import tech.pegasys.web3signer.core.service.http.metrics.HttpApiMetrics;
import tech.pegasys.web3signer.core.util.DepositSigningRootUtil;
import tech.pegasys.web3signer.slashingprotection.SlashingProtection;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.MIMEHeader;
import io.vertx.ext.web.RequestBody;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt64;
import org.hyperledger.besu.plugin.services.metrics.OperationTimer.TimingContext;

public class Eth2SignForIdentifierHandler implements Handler<RoutingContext> {

  private static final Logger LOG = LogManager.getLogger();
  private final SignerForIdentifier signerForIdentifier;
  private final HttpApiMetrics httpMetrics;
  private final SlashingProtectionMetrics slashingMetrics;
  private final Optional<SlashingProtection> slashingProtection;
  private final ObjectMapper objectMapper;
  private final Spec eth2Spec;
  private final SigningRootUtil signingRootUtil;

  public static final int NOT_FOUND = 404;
  public static final int BAD_REQUEST = 400;
  public static final int SLASHING_PROTECTION_ENFORCED = 412;

  public Eth2SignForIdentifierHandler(
      final SignerForIdentifier signerForIdentifier,
      final HttpApiMetrics httpMetrics,
      final SlashingProtectionMetrics slashingMetrics,
      final Optional<SlashingProtection> slashingProtection,
      final ObjectMapper objectMapper,
      final Spec eth2Spec) {
    this.signerForIdentifier = signerForIdentifier;
    this.httpMetrics = httpMetrics;
    this.slashingMetrics = slashingMetrics;
    this.slashingProtection = slashingProtection;
    this.objectMapper = objectMapper;
    this.eth2Spec = eth2Spec;
    this.signingRootUtil = new SigningRootUtil(eth2Spec);
  }

  @Override
  public void handle(final RoutingContext routingContext) {
    try (final TimingContext ignored = httpMetrics.getSigningTimer().startTimer()) {
      LOG.trace("{} || {}", routingContext.normalizedPath(), routingContext.body().asString());
      final String identifier = routingContext.pathParam("identifier");
      final Eth2SigningRequestBody eth2SigningRequestBody;
      try {
        eth2SigningRequestBody = getSigningRequest(routingContext.body());
      } catch (final IllegalArgumentException | JsonProcessingException e) {
        handleInvalidRequest(routingContext, e);
        return;
      }

      final Bytes signingRoot = computeSigningRoot(eth2SigningRequestBody);
      if (eth2SigningRequestBody.signingRoot() != null) {
        checkArgument(
            eth2SigningRequestBody.signingRoot().equals(signingRoot),
            "Signing root %s must match signing computed signing root %s from data",
            eth2SigningRequestBody.signingRoot(),
            signingRoot);
      }

      final String normalisedIdentifier = normaliseIdentifier(identifier);
      if (slashingProtection.isPresent()) {
        handleSigning(
            routingContext,
            signingRoot,
            normalisedIdentifier,
            signature ->
                signWithSlashingProtection(
                    routingContext, identifier, eth2SigningRequestBody, signingRoot, signature));
      } else {
        handleSigning(
            routingContext,
            signingRoot,
            normalisedIdentifier,
            signature -> respondWithSignature(routingContext, signature));
      }
    }
  }

  private void handleSigning(
      final RoutingContext routingContext,
      final Bytes signingRoot,
      final String normalisedIdentifier,
      final Consumer<String> signatureConsumer) {
    signerForIdentifier
        .sign(normalisedIdentifier, signingRoot)
        .ifPresentOrElse(
            signatureConsumer,
            () -> {
              httpMetrics.getMissingSignerCounter().inc();
              routingContext.fail(NOT_FOUND);
            });
  }

  private void signWithSlashingProtection(
      final RoutingContext routingContext,
      final String identifier,
      final Eth2SigningRequestBody eth2SigningRequestBody,
      final Bytes signingRoot,
      final String signature) {
    try {
      if (maySign(Bytes.fromHexString(identifier), signingRoot, eth2SigningRequestBody)) {
        slashingMetrics.incrementSigningsPermitted();
        respondWithSignature(routingContext, signature);
      } else {
        slashingMetrics.incrementSigningsPrevented();
        LOG.debug("Signing not allowed due to slashing protection rules failing");
        routingContext.fail(SLASHING_PROTECTION_ENFORCED);
      }
    } catch (final IllegalArgumentException e) {
      handleInvalidRequest(routingContext, e);
    }
  }

  private void handleInvalidRequest(final RoutingContext routingContext, final Exception e) {
    httpMetrics.getMalformedRequestCounter().inc();
    LOG.debug("Invalid signing request - " + routingContext.body().asString(), e);
    routingContext.fail(BAD_REQUEST);
  }

  private boolean maySign(
      final Bytes publicKey,
      final Bytes signingRoot,
      final Eth2SigningRequestBody eth2SigningRequestBody) {
    final ForkInfo forkInfo = eth2SigningRequestBody.forkInfo();
    switch (eth2SigningRequestBody.type()) {
      case BLOCK, BLOCK_V2 -> {
        try (final TimingContext ignored =
            slashingMetrics.getDatabaseTimer().labels("block").startTimer()) {
          return maySignBlock(
              publicKey, signingRoot, getBlockSlot(eth2SigningRequestBody), forkInfo);
        }
      }
      case ATTESTATION -> {
        final AttestationData attestation = eth2SigningRequestBody.attestation();
        try (final TimingContext ignored =
            slashingMetrics.getDatabaseTimer().labels("attestation").startTimer()) {
          return slashingProtection
              .get()
              .maySignAttestation(
                  publicKey,
                  signingRoot,
                  toUInt64(attestation.source.epoch),
                  toUInt64(attestation.target.epoch),
                  forkInfo.getGenesisValidatorsRoot());
        }
      }
      default -> {
        return true;
      }
    }
  }

  private UInt64 getBlockSlot(final Eth2SigningRequestBody eth2SigningRequestBody) {
    final UInt64 blockSlot;
    if (eth2SigningRequestBody.type() == ArtifactType.BLOCK) {
      blockSlot = UInt64.valueOf(eth2SigningRequestBody.block().slot.bigIntegerValue());
    } else {
      final BlockRequest blockRequest = eth2SigningRequestBody.blockRequest();
      blockSlot =
          switch (blockRequest.getVersion()) {
            case PHASE0, ALTAIR ->
                UInt64.valueOf(blockRequest.getBeaconBlock().slot.bigIntegerValue());
            default -> UInt64.valueOf(blockRequest.getBeaconBlockHeader().slot.bigIntegerValue());
          };
    }

    return blockSlot;
  }

  private boolean maySignBlock(
      final Bytes publicKey,
      final Bytes signingRoot,
      final UInt64 blockSlot,
      final ForkInfo forkInfo) {
    return slashingProtection
        .get()
        .maySignBlock(publicKey, signingRoot, blockSlot, forkInfo.getGenesisValidatorsRoot());
  }

  private Bytes computeSigningRoot(final Eth2SigningRequestBody body) {
    switch (body.type()) {
      case BLOCK -> {
        checkArgument(body.block() != null, "block must be specified");
        return signingRootUtil.signingRootForSignBlock(
            body.block().asInternalBeaconBlock(eth2Spec), body.forkInfo().asInternalForkInfo());
      }
      case BLOCK_V2 -> {
        checkArgument(body.blockRequest() != null, "beacon_block must be specified");

        return switch (body.blockRequest().getVersion()) {
          case PHASE0, ALTAIR ->
              signingRootUtil.signingRootForSignBlock(
                  body.blockRequest().getBeaconBlock().asInternalBeaconBlock(eth2Spec),
                  body.forkInfo().asInternalForkInfo());
          default ->
              signingRootUtil.signingRootForSignBlockHeader(
                  body.blockRequest().getBeaconBlockHeader().asInternalBeaconBlockHeader(),
                  body.forkInfo().asInternalForkInfo());
        };
      }
      case ATTESTATION -> {
        checkArgument(body.attestation() != null, "attestation must be specified");
        return signingRootUtil.signingRootForSignAttestationData(
            body.attestation().asInternalAttestationData(), body.forkInfo().asInternalForkInfo());
      }
      case AGGREGATE_AND_PROOF, AGGREGATE_AND_PROOF_V2 -> {
        checkArgument(body.aggregateAndProofV2() != null, "aggregateAndProof must be specified");
        return signingRootUtil.signingRootForSignAggregateAndProof(
            body.aggregateAndProofV2().data().asInternalAggregateAndProof(eth2Spec),
            body.forkInfo().asInternalForkInfo());
      }
      case AGGREGATION_SLOT -> {
        checkArgument(body.aggregationSlot() != null, "aggregationSlot must be specified");
        return signingRootUtil.signingRootForSignAggregationSlot(
            body.aggregationSlot().getSlot(), body.forkInfo().asInternalForkInfo());
      }
      case RANDAO_REVEAL -> {
        checkArgument(body.randaoReveal() != null, "randaoReveal must be specified");
        return signingRootUtil.signingRootForRandaoReveal(
            body.randaoReveal().getEpoch(), body.forkInfo().asInternalForkInfo());
      }
      case VOLUNTARY_EXIT -> {
        checkArgument(body.voluntaryExit() != null, "voluntaryExit must be specified");
        return signingRootUtil.signingRootForSignVoluntaryExit(
            body.voluntaryExit().asInternalVoluntaryExit(), body.forkInfo().asInternalForkInfo());
      }
      case DEPOSIT -> {
        checkArgument(body.deposit() != null, "deposit must be specified");
        final Bytes32 depositDomain =
            computeDomain(Domain.DEPOSIT, body.deposit().getGenesisForkVersion(), Bytes32.ZERO);
        return DepositSigningRootUtil.computeSigningRoot(
            body.deposit().asInternalDepositMessage(), depositDomain);
      }
      case SYNC_COMMITTEE_MESSAGE -> {
        final SyncCommitteeMessage syncCommitteeMessage = body.syncCommitteeMessage();
        checkArgument(syncCommitteeMessage != null, "SyncCommitteeMessage must be specified");
        return signingRootFromSyncCommitteeUtils(
            syncCommitteeMessage.getSlot(),
            utils ->
                utils.getSyncCommitteeMessageSigningRoot(
                    syncCommitteeMessage.getBeaconBlockRoot(),
                    eth2Spec.computeEpochAtSlot(syncCommitteeMessage.getSlot()),
                    body.forkInfo().asInternalForkInfo()));
      }
      case SYNC_COMMITTEE_SELECTION_PROOF -> {
        final SyncAggregatorSelectionData syncAggregatorSelectionData =
            body.syncAggregatorSelectionData();
        checkArgument(
            syncAggregatorSelectionData != null, "SyncAggregatorSelectionData is required");
        return signingRootFromSyncCommitteeUtils(
            syncAggregatorSelectionData.getSlot(),
            utils ->
                utils.getSyncAggregatorSelectionDataSigningRoot(
                    asInternalSyncAggregatorSelectionData(syncAggregatorSelectionData),
                    body.forkInfo().asInternalForkInfo()));
      }
      case SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF -> {
        final ContributionAndProof contributionAndProof = body.contributionAndProof();
        checkArgument(contributionAndProof != null, "ContributionAndProof is required");
        return signingRootFromSyncCommitteeUtils(
            contributionAndProof.contribution.slot,
            utils ->
                utils.getContributionAndProofSigningRoot(
                    asInternalContributionAndProof(contributionAndProof),
                    body.forkInfo().asInternalForkInfo()));
      }
      case VALIDATOR_REGISTRATION -> {
        final ValidatorRegistration validatorRegistration = body.validatorRegistration();
        checkArgument(validatorRegistration != null, "ValidatorRegistration is required");
        return signingRootUtil.signingRootForValidatorRegistration(
            validatorRegistration.asInternalValidatorRegistration());
      }
      case EXECUTION_PAYLOAD_BID -> {
        final VersionedRequest<ExecutionPayloadBid> request = body.executionPayloadBid();
        final SpecVersion specVersion = specVersionFor(request, "execution_payload_bid");
        return signingRootUtil.signingRootForSignExecutionPayloadBid(
            request.data().asInternalExecutionPayloadBid(specVersion),
            body.forkInfo().asInternalForkInfo());
      }
      case EXECUTION_PAYLOAD_ENVELOPE -> {
        final VersionedRequest<ExecutionPayloadEnvelope> request = body.executionPayloadEnvelope();
        final SpecVersion specVersion = specVersionFor(request, "execution_payload_envelope");
        return signingRootUtil.signingRootForSignExecutionPayloadEnvelope(
            request.data().asInternalExecutionPayloadEnvelope(specVersion),
            body.forkInfo().asInternalForkInfo());
      }
      case PAYLOAD_ATTESTATION_MESSAGE -> {
        final VersionedRequest<PayloadAttestationData> request = body.payloadAttestationMessage();
        final SpecVersion specVersion = specVersionFor(request, "payload_attestation_message");
        return signingRootUtil.signingRootForSignPayloadAttestationData(
            request.data().asInternalPayloadAttestationData(specVersion),
            body.forkInfo().asInternalForkInfo());
      }
      case PROPOSER_PREFERENCES -> {
        final VersionedRequest<ProposerPreferences> request = body.proposerPreferences();
        final SpecVersion specVersion = specVersionFor(request, "proposer_preferences");
        return signingRootUtil.signingRootForSignProposerPreferences(
            request.data().asInternalProposerPreferences(specVersion),
            body.forkInfo().asInternalForkInfo());
      }
      case BUILDER_REQUEST_AUTH -> {
        final VersionedRequest<BuilderRequestAuth> request = body.builderRequestAuth();
        specVersionFor(request, "builder_request_auth");
        return signingRootUtil.signingRootForSignBuilderRequestAuth(
            request.data().asInternalBuilderRequestAuth());
      }
      default ->
          throw new IllegalStateException("Signing root unimplemented for type " + body.type());
    }
  }

  /**
   * Validates a fork-versioned payload and resolves the {@link SpecVersion} for its declared
   * milestone. Rejects requests whose milestone is not scheduled on the configured network.
   */
  private SpecVersion specVersionFor(final VersionedRequest<?> request, final String field) {
    checkArgument(request != null, "%s is required", field);
    checkArgument(request.version() != null, "%s.version is required", field);
    checkArgument(request.data() != null, "%s.data is required", field);
    final SpecVersion specVersion = eth2Spec.forMilestone(request.version());
    checkArgument(
        specVersion != null,
        "%s.version %s is not scheduled on the configured network",
        field,
        request.version());
    return specVersion;
  }

  private tech.pegasys.teku.spec.datastructures.operations.versions.altair
          .SyncAggregatorSelectionData
      asInternalSyncAggregatorSelectionData(
          final SyncAggregatorSelectionData syncAggregatorSelectionData) {
    return SyncAggregatorSelectionDataSchema.INSTANCE.create(
        syncAggregatorSelectionData.getSlot(), syncAggregatorSelectionData.getSubcommitteeIndex());
  }

  private tech.pegasys.teku.spec.datastructures.operations.versions.altair.ContributionAndProof
      asInternalContributionAndProof(final ContributionAndProof contributionAndProof) {
    final tech.pegasys.teku.spec.datastructures.operations.versions.altair.SyncCommitteeContribution
        syncCommitteeContribution =
            SyncCommitteeContribution.asInternalSyncCommitteeContribution(
                eth2Spec, contributionAndProof.contribution);
    return eth2Spec
        .getSyncCommitteeUtilRequired(contributionAndProof.contribution.slot)
        .createContributionAndProof(
            contributionAndProof.aggregatorIndex,
            syncCommitteeContribution,
            contributionAndProof.selectionProof.asInternalBLSSignature());
  }

  private Bytes signingRootFromSyncCommitteeUtils(
      final tech.pegasys.teku.infrastructure.unsigned.UInt64 slot,
      final Function<SyncCommitteeUtil, Bytes> createSigningRoot) {
    return createSigningRoot.apply(eth2Spec.getSyncCommitteeUtilRequired(slot));
  }

  private UInt64 toUInt64(final tech.pegasys.teku.infrastructure.unsigned.UInt64 uInt64) {
    return UInt64.valueOf(uInt64.bigIntegerValue());
  }

  private void respondWithSignature(final RoutingContext routingContext, final String signature) {
    final String acceptableContentType =
        getAcceptableContentType(routingContext.parsedHeaders().accept());
    LOG.trace("Acceptable Content Type {}", acceptableContentType);
    final String body =
        acceptableContentType.equals(JSON_UTF_8)
            ? new JsonObject().put("signature", signature).encode()
            : signature;
    routingContext.response().putHeader(CONTENT_TYPE, acceptableContentType).end(body);
  }

  private Eth2SigningRequestBody getSigningRequest(final RequestBody requestBody)
      throws JsonProcessingException {
    final String body = requestBody.asString();
    return objectMapper.readValue(body, Eth2SigningRequestBody.class);
  }

  private String getAcceptableContentType(final List<MIMEHeader> mimeHeaders) {
    return mimeHeaders.stream()
        .filter(this::isJsonCompatibleHeader)
        .findAny()
        .map(mimeHeader -> JSON_UTF_8)
        .orElse(TEXT_PLAIN_UTF_8);
  }

  private boolean isJsonCompatibleHeader(final MIMEHeader mimeHeader) {
    final String mimeType =
        mimeHeader.value(); // Must use value() rather than component() to ensure header is parsed
    return "application/json".equalsIgnoreCase(mimeType) || "*/*".equalsIgnoreCase(mimeType);
  }
}
