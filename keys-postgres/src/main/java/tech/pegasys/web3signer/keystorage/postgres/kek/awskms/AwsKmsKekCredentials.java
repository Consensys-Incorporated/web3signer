/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres.kek.awskms;

import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.common.config.AwsCredentials;

import java.net.URI;
import java.util.Optional;

/**
 * Credentials for the AWS KMS-backed {@code KekResolver}. Deliberately not shared with the existing
 * Azure/AWS bulk-secret-scan CLI parameters - "unwrap N specific keys" and "list an entire vault"
 * are different privilege scopes that may reasonably use different identities.
 */
public interface AwsKmsKekCredentials {

  AwsAuthenticationMode getAuthenticationMode();

  Optional<AwsCredentials> getCredentials();

  Optional<URI> getEndpointOverride();
}
