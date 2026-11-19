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
 * Answer to {@code LOAD_KEYS}.
 *
 * @param loaded entries added to the key set
 * @param duplicates entries whose public key was already loaded
 * @param rejected entries that failed authentication or the key checks
 */
public record LoadResult(long loaded, long duplicates, long rejected) {
  public static final LoadResult EMPTY = new LoadResult(0, 0, 0);

  public LoadResult plus(final LoadResult other) {
    return new LoadResult(
        loaded + other.loaded, duplicates + other.duplicates, rejected + other.rejected);
  }
}
