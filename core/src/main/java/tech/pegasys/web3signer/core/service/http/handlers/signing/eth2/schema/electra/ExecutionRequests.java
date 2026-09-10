/*
 * Copyright 2025 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.electra;

import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequestsBuilder;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionRequestsSchema;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.ConsolidationRequestSchema;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.DepositRequestSchema;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.WithdrawalRequestSchema;
import tech.pegasys.teku.spec.datastructures.execution.versions.gloas.BuilderDepositRequestSchema;
import tech.pegasys.teku.spec.datastructures.execution.versions.gloas.BuilderExitRequestSchema;
import tech.pegasys.teku.spec.datastructures.execution.versions.gloas.ExecutionRequestsSchemaGloas;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;

public class ExecutionRequests {

  @JsonProperty("deposits")
  private final List<DepositRequest> deposits;

  @JsonProperty("withdrawals")
  private final List<WithdrawalRequest> withdrawals;

  @JsonProperty("consolidations")
  private final List<ConsolidationRequest> consolidations;

  // Gloas (ePBS) additions, EIP-8282. Absent on pre-Gloas forks.
  @JsonProperty("builder_deposits")
  private final List<BuilderDepositRequest> builderDeposits;

  @JsonProperty("builder_exits")
  private final List<BuilderExitRequest> builderExits;

  public ExecutionRequests(
      @JsonProperty("deposits") final List<DepositRequest> deposits,
      @JsonProperty("withdrawals") final List<WithdrawalRequest> withdrawals,
      @JsonProperty("consolidations") final List<ConsolidationRequest> consolidations,
      @JsonProperty("builder_deposits") final List<BuilderDepositRequest> builderDeposits,
      @JsonProperty("builder_exits") final List<BuilderExitRequest> builderExits) {
    this.deposits = deposits;
    this.withdrawals = withdrawals;
    this.consolidations = consolidations;
    this.builderDeposits = MoreObjects.firstNonNull(builderDeposits, List.of());
    this.builderExits = MoreObjects.firstNonNull(builderExits, List.of());
  }

  public ExecutionRequests(
      final tech.pegasys.teku.spec.datastructures.execution.ExecutionRequests executionRequests) {
    this.deposits = executionRequests.getDeposits().stream().map(DepositRequest::new).toList();
    this.withdrawals =
        executionRequests.getWithdrawals().stream().map(WithdrawalRequest::new).toList();
    this.consolidations =
        executionRequests.getConsolidations().stream().map(ConsolidationRequest::new).toList();
    if (executionRequests
        instanceof
        tech.pegasys.teku.spec.datastructures.execution.versions.gloas.ExecutionRequestsGloas
            gloasRequests) {
      this.builderDeposits =
          gloasRequests.getBuilderDeposits().stream().map(BuilderDepositRequest::new).toList();
      this.builderExits =
          gloasRequests.getBuilderExits().stream().map(BuilderExitRequest::new).toList();
    } else {
      this.builderDeposits = List.of();
      this.builderExits = List.of();
    }
  }

  /**
   * Builds the internal execution requests for the given schema. Electra schemas ignore builder
   * deposits/exits (no-op); Gloas schemas (EIP-8282) require them.
   */
  public final tech.pegasys.teku.spec.datastructures.execution.ExecutionRequests
      asInternalExecutionRequests(final ExecutionRequestsSchema<?> schema) {

    final DepositRequestSchema depositSchema =
        (DepositRequestSchema) schema.getDepositRequestsSchema().getElementSchema();
    final WithdrawalRequestSchema withdrawalSchema =
        (WithdrawalRequestSchema) schema.getWithdrawalRequestsSchema().getElementSchema();
    final ConsolidationRequestSchema consolidationSchema =
        (ConsolidationRequestSchema) schema.getConsolidationRequestsSchema().getElementSchema();

    final List<tech.pegasys.teku.spec.datastructures.execution.versions.electra.DepositRequest>
        depositsInternal =
            deposits.stream()
                .map(depositRequest -> depositRequest.asInternalDepositRequest(depositSchema))
                .toList();
    final List<tech.pegasys.teku.spec.datastructures.execution.versions.electra.WithdrawalRequest>
        withdrawalsInternal =
            withdrawals.stream()
                .map(
                    withdrawalRequest ->
                        withdrawalRequest.asInternalWithdrawalRequest(withdrawalSchema))
                .toList();
    final List<
            tech.pegasys.teku.spec.datastructures.execution.versions.electra.ConsolidationRequest>
        consolidationsInternal =
            consolidations.stream()
                .map(
                    consolidationRequest ->
                        consolidationRequest.asInternalConsolidationRequest(consolidationSchema))
                .toList();

    final ExecutionRequestsBuilder builder = schema.createBuilder();
    builder.deposits(depositsInternal);
    builder.withdrawals(withdrawalsInternal);
    builder.consolidations(consolidationsInternal);

    if (schema instanceof ExecutionRequestsSchemaGloas gloasSchema) {
      final BuilderDepositRequestSchema builderDepositSchema =
          (BuilderDepositRequestSchema)
              gloasSchema.getBuilderDepositRequestsSchema().getElementSchema();
      final BuilderExitRequestSchema builderExitSchema =
          (BuilderExitRequestSchema) gloasSchema.getBuilderExitRequestsSchema().getElementSchema();
      final List<
              tech.pegasys.teku.spec.datastructures.execution.versions.gloas.BuilderDepositRequest>
          builderDepositsInternal =
              builderDeposits.stream()
                  .map(
                      builderDepositRequest ->
                          builderDepositRequest.asInternalBuilderDepositRequest(
                              builderDepositSchema))
                  .toList();
      final List<tech.pegasys.teku.spec.datastructures.execution.versions.gloas.BuilderExitRequest>
          builderExitsInternal =
              builderExits.stream()
                  .map(
                      builderExitRequest ->
                          builderExitRequest.asInternalBuilderExitRequest(builderExitSchema))
                  .toList();
      builder.builderDeposits(() -> builderDepositsInternal);
      builder.builderExits(() -> builderExitsInternal);
    }

    return builder.build();
  }
}
