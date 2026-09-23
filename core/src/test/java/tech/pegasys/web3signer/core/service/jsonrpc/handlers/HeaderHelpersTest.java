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
package tech.pegasys.web3signer.core.service.jsonrpc.handlers;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import com.google.common.collect.Lists;
import com.google.common.net.HttpHeaders;
import io.vertx.core.MultiMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HeaderHelpersTest {

  @ParameterizedTest
  @ValueSource(strings = {"ORIGIN", "origin", "Origin", "OrIgIn"})
  void originHeaderIsRemoved(String headerToRemove) {
    final MultiMap input = MultiMap.caseInsensitiveMultiMap();
    input.add(headerToRemove, "arbitrary");
    final MultiMap output = HeaderHelpers.createHeaders(input);

    assertThat(output.get(headerToRemove)).isNull();
  }

  @ParameterizedTest
  @ValueSource(strings = {"CONTENT-LENGTH", "content-length", "Content-Length", "CoNtEnT-LeNgTh"})
  void contentLengthHeaderIsRemoved(String headerToRemove) {
    final MultiMap input = MultiMap.caseInsensitiveMultiMap();
    input.add(headerToRemove, "arbitrary");
    final MultiMap output = HeaderHelpers.createHeaders(input);

    assertThat(output.get(headerToRemove)).isNull();
  }

  @Test
  void hostHeaderIsRenamedToXForwardedHost() {
    final MultiMap input = MultiMap.caseInsensitiveMultiMap();
    input.add(HttpHeaders.HOST, "arbitrary");

    final MultiMap output = HeaderHelpers.createHeaders(input);

    assertThat(output.get(HttpHeaders.HOST)).isNull();
    assertThat(output.get(HttpHeaders.X_FORWARDED_HOST)).isEqualTo("arbitrary");
  }

  @Test
  void ensureMultiEntryHeadersAreCopiedCorrectly() {
    final MultiMap input = MultiMap.caseInsensitiveMultiMap();
    final List<String> headerValues = Lists.newArrayList("arbitrary", "secondArbitrary");
    input.add(HttpHeaders.HOST, headerValues);

    final MultiMap output = HeaderHelpers.createHeaders(input);

    assertThat(output.getAll(HttpHeaders.X_FORWARDED_HOST))
        .containsExactlyInAnyOrder("arbitrary", "secondArbitrary");
  }
}
