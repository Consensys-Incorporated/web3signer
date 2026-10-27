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
package tech.pegasys.web3signer.signing.config;

import java.util.Optional;

public final class GcpSecretManagerParametersBuilder {
  private boolean enabled;
  private String projectId;
  private Optional<String> filter = Optional.empty();

  private GcpSecretManagerParametersBuilder() {}

  public static GcpSecretManagerParametersBuilder aGcpParameters() {
    return new GcpSecretManagerParametersBuilder();
  }

  public GcpSecretManagerParametersBuilder withEnabled(final boolean enabled) {
    this.enabled = enabled;
    return this;
  }

  public GcpSecretManagerParametersBuilder withProjectId(final String projectId) {
    this.projectId = projectId;
    return this;
  }

  public GcpSecretManagerParametersBuilder withFilter(final String filter) {
    this.filter = Optional.of(filter);
    return this;
  }

  public GcpSecretManagerParameters build() {
    return new TestGcpSecretManagerParameters(enabled, projectId, filter);
  }

  private static class TestGcpSecretManagerParameters implements GcpSecretManagerParameters {
    private final boolean enabled;
    private final String projectId;
    private final Optional<String> filter;

    private TestGcpSecretManagerParameters(
        boolean enabled, String projectId, Optional<String> filter) {
      this.enabled = enabled;
      this.projectId = projectId;
      this.filter = filter;
    }

    @Override
    public boolean isEnabled() {
      return enabled;
    }

    @Override
    public String getProjectId() {
      return projectId;
    }

    @Override
    public Optional<String> getFilter() {
      return filter;
    }
  }
}
