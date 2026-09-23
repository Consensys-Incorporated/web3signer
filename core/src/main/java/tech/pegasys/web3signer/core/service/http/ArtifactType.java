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

public enum ArtifactType {
  BLOCK,
  BLOCK_V2,
  ATTESTATION,
  AGGREGATION_SLOT,
  @Deprecated(since = "1.2.0") // Deprecated in Remoting API Spec v1.2.0
  AGGREGATE_AND_PROOF,
  AGGREGATE_AND_PROOF_V2,
  DEPOSIT,
  RANDAO_REVEAL,
  VOLUNTARY_EXIT,
  SYNC_COMMITTEE_MESSAGE,
  SYNC_COMMITTEE_SELECTION_PROOF,
  SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
  VALIDATOR_REGISTRATION,
  EXECUTION_PAYLOAD_BID,
  EXECUTION_PAYLOAD_ENVELOPE,
  PAYLOAD_ATTESTATION_MESSAGE,
  PROPOSER_PREFERENCES,
  BUILDER_REQUEST_AUTH
}
