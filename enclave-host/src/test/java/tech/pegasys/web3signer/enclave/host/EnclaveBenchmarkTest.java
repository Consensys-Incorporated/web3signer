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
package tech.pegasys.web3signer.enclave.host;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.Test;

class EnclaveBenchmarkTest {

  @Test
  void signsEveryRequestAndVerifiesTheSamples() throws Exception {
    try (InProcessEnclaveSigner signer = new InProcessEnclaveSigner()) {
      EnclaveTestKeys.provision(signer.address(), EnclaveTestKeys.randomKeys(2));
      final StringWriter text = new StringWriter();
      try (EnclaveClient client =
          EnclaveClient.create(signer.address(), new EnclaveClient.Options(2, 30_000))) {
        final EnclaveBenchmark.Result result =
            EnclaveBenchmark.run(
                client, new EnclaveBenchmark.Options(2, 50, true), new PrintWriter(text, true));
        assertThat(result.failures()).isZero();
        assertThat(result.verifyFailures()).isZero();
        assertThat(result.signsPerSecond()).isPositive();
        assertThat(result.p50()).isPositive().isLessThanOrEqualTo(result.p99());
      }
      assertThat(text.toString()).contains("verified 50 signatures, 0 mismatches");
    }
  }
}
