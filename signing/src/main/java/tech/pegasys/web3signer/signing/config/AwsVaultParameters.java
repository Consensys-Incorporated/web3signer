/*
 * Copyright 2022 ConsenSys AG.
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
package tech.pegasys.web3signer.signing.config;

import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public interface AwsVaultParameters {
  boolean isEnabled();

  AwsAuthenticationMode getAuthenticationMode();

  String getAccessKeyId();

  String getSecretAccessKey();

  String getRegion();

  default long getCacheMaximumSize() {
    return 1;
  }

  default Collection<String> getPrefixesFilter() {
    return Collections.emptyList();
  }

  Map<String, String> getTags();

  /**
   * Can be used to override AWS endpoint to an AWS emulator
   *
   * @return optional URI
   */
  Optional<URI> getEndpointOverride();
}
