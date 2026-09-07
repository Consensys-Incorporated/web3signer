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
package tech.pegasys.web3signer.signing.config;

import java.nio.file.Path;
import java.time.Duration;

public interface PostgresKeystoreParameters {
  boolean isEnabled();

  String getDbUrl();

  String getDbUsername();

  String getDbPassword();

  Path getDbPoolConfigurationFile();

  default Duration getDekCacheTtl() {
    return Duration.ofMinutes(15);
  }

  default int getDecryptionParallelism() {
    return 8;
  }

  default long getDbHealthCheckTimeoutMilliseconds() {
    return 3000;
  }
}
