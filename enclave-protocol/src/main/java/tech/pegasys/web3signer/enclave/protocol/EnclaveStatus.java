/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.enclave.protocol;

/**
 * Answer to {@code STATUS}.
 *
 * @param protocolVersion protocol version of the signer
 * @param platform {@link Protocol#PLATFORM_DEV} or {@link Protocol#PLATFORM_AWS_NITRO}
 * @param cpus processors available to the signer
 * @param keyCount number of loaded keys
 * @param bootId 16 random bytes chosen at signer start, as hex
 * @param version implementation version of the signer
 */
public record EnclaveStatus(
    int protocolVersion, int platform, int cpus, long keyCount, String bootId, String version) {

  public String platformName() {
    return Protocol.platformName(platform);
  }
}
