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

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.web3signer.enclave.client.EnclaveClient;

import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes48;

/**
 * Signing benchmark against an enclave signer: {@code callers} threads make {@code requests} {@code
 * sign()} calls with random 32-byte messages over the keys the enclave holds.
 */
public final class EnclaveBenchmark {
  private static final int BASELINE_SIGNATURES = 2000;
  private static final int VERIFIED_SIGNATURES = 200;
  private static final SecureRandom RANDOM = new SecureRandom();

  private EnclaveBenchmark() {}

  /**
   * Benchmark settings.
   *
   * @param callers threads calling {@code sign()}
   * @param requests total number of calls
   * @param verify check the first 200 signatures with Teku
   */
  public record Options(int callers, int requests, boolean verify) {
    public Options {
      if (callers < 1 || requests < 1) {
        throw new IllegalArgumentException("callers and requests must be at least 1");
      }
    }
  }

  /**
   * Results; latencies in microseconds.
   *
   * @param signsPerSecond throughput over the whole run
   * @param p50 median latency
   * @param p95 95th percentile latency
   * @param p99 99th percentile latency
   * @param baselineMicros one local Teku {@code BLS.sign}, averaged
   * @param failures calls that threw
   * @param verifyFailures signatures that did not verify
   */
  public record Result(
      double signsPerSecond,
      double p50,
      double p95,
      double p99,
      double baselineMicros,
      int failures,
      int verifyFailures) {}

  @SuppressWarnings("ArrayRecordComponent")
  private record Sample(byte[] publicKey, byte[] message, byte[] signature) {}

  public static Result run(final EnclaveClient client, final Options options, final PrintWriter out)
      throws InterruptedException {
    final List<byte[]> keys = client.publicKeys();
    if (keys.isEmpty()) {
      throw new EnclaveHostException("The enclave holds no keys");
    }
    final double baseline = baselineMicros();
    out.printf(
        Locale.ROOT,
        "keys %d, callers %d, requests %d, local BLS.sign baseline %.1f us%n",
        keys.size(),
        options.callers(),
        options.requests(),
        baseline);

    final long[] latencies = new long[options.requests()];
    final AtomicInteger next = new AtomicInteger();
    final AtomicInteger failures = new AtomicInteger();
    final AtomicReference<RuntimeException> firstFailure = new AtomicReference<>();
    final Sample[] samples = new Sample[Math.min(VERIFIED_SIGNATURES, options.requests())];
    final List<Thread> threads = new ArrayList<>();
    final long start = System.nanoTime();
    for (int t = 0; t < options.callers(); t++) {
      threads.add(
          Thread.ofPlatform()
              .start(
                  () -> {
                    final byte[] message = new byte[32];
                    int index;
                    while ((index = next.getAndIncrement()) < options.requests()) {
                      ThreadLocalRandom.current().nextBytes(message);
                      final byte[] publicKey =
                          keys.get(ThreadLocalRandom.current().nextInt(keys.size()));
                      final long begin = System.nanoTime();
                      try {
                        final byte[] signature = client.sign(publicKey, message);
                        latencies[index] = System.nanoTime() - begin;
                        if (index < samples.length) {
                          samples[index] = new Sample(publicKey, message.clone(), signature);
                        }
                      } catch (final RuntimeException e) {
                        latencies[index] = System.nanoTime() - begin;
                        failures.incrementAndGet();
                        firstFailure.compareAndSet(null, e);
                      }
                    }
                  }));
    }
    for (final Thread thread : threads) {
      thread.join();
    }
    final double seconds = (System.nanoTime() - start) / 1e9;

    int verifyFailures = 0;
    if (options.verify()) {
      for (final Sample sample : samples) {
        if (sample != null && !verifies(sample)) {
          verifyFailures++;
        }
      }
    }
    Arrays.sort(latencies);
    final Result result =
        new Result(
            options.requests() / seconds,
            percentile(latencies, 0.50),
            percentile(latencies, 0.95),
            percentile(latencies, 0.99),
            baseline,
            failures.get(),
            verifyFailures);
    out.printf(
        Locale.ROOT,
        "%.0f signs/s, p50 %.0f us, p95 %.0f us, p99 %.0f us%n",
        result.signsPerSecond(),
        result.p50(),
        result.p95(),
        result.p99());
    if (result.failures() > 0) {
      out.printf(
          Locale.ROOT,
          "%d calls failed, first: %s%n",
          result.failures(),
          firstFailure.get().getMessage());
    }
    if (options.verify()) {
      out.printf(
          Locale.ROOT,
          "verified %d signatures, %d mismatches%n",
          Arrays.stream(samples).filter(s -> s != null).count(),
          verifyFailures);
    }
    return result;
  }

  private static boolean verifies(final Sample sample) {
    try {
      return BLS.verify(
          BLSPublicKey.fromBytesCompressed(Bytes48.wrap(sample.publicKey())),
          Bytes.wrap(sample.message()),
          BLSSignature.fromBytesCompressed(Bytes.wrap(sample.signature())));
    } catch (final RuntimeException e) {
      return false;
    }
  }

  private static double percentile(final long[] sortedNanos, final double fraction) {
    final int index =
        (int) Math.min(sortedNanos.length - 1, Math.ceil(fraction * sortedNanos.length) - 1);
    return sortedNanos[Math.max(0, index)] / 1000.0;
  }

  /** One Teku {@code BLS.sign} in this JVM, averaged over 2,000 calls after a warm-up. */
  static double baselineMicros() {
    final BLSKeyPair key = BLSKeyPair.random(RANDOM);
    final byte[] message = new byte[32];
    for (int i = 0; i < BASELINE_SIGNATURES / 2; i++) {
      message[0] = (byte) i;
      BLS.sign(key.getSecretKey(), Bytes.wrap(message.clone())).toBytesCompressed();
    }
    final long start = System.nanoTime();
    for (int i = 0; i < BASELINE_SIGNATURES; i++) {
      message[0] = (byte) i;
      message[1] = (byte) (i >> 8);
      BLS.sign(key.getSecretKey(), Bytes.wrap(message.clone())).toBytesCompressed();
    }
    return (System.nanoTime() - start) / 1000.0 / BASELINE_SIGNATURES;
  }
}
