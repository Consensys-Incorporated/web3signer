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
package tech.pegasys.web3signer.core.config;

public interface HealthCheckNames {
  String DEFAULT_CHECK = "default-check";
  String SLASHING_PROTECTION_DB = "slashing-protection-db-health-check";
  String KEYS_CHECK_UNEXPECTED = "keys-check/unexpected";
  String KEYS_CHECK_AWS_BULK_LOADING = "keys-check/aws-bulk-loading";
  String KEYS_CHECK_GCP_BULK_LOADING = "keys-check/gcp-bulk-loading";
  String KEYS_CHECK_AZURE_BULK_LOADING = "keys-check/azure-bulk-loading";
  String KEYS_CHECK_KEYSTORE_BULK_LOADING = "keys-check/keystores-bulk-loading";
  String KEYS_CHECK_CONFIG_FILE_LOADING = "keys-check/config-files-loading";
  String KEYS_CHECK_V3_KEYSTORES_BULK_LOADING = "keys-check/v3-keystores-bulk-loading";
  String KEYS_CHECK_POSTGRES_BULK_LOADING = "keys-check/postgres-bulk-loading";
}
