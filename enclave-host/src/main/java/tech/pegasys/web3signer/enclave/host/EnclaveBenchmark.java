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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
   * Results; latencies in microseconds, over the calls that succeeded.
   *
   * @param signsPerSecond successful signatures per second over the whole run
   * @param p50 median latency; NaN when no call succeeded
   * @param p95 95th percentile latency; NaN when no call succeeded
   * @param p99 99th percentile latency; NaN when no call succeeded
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

  /** The state the calling threads share. Each call writes only its own slots. */
  private static final class Calls {
    private static final long FAILED = -1;

    private final EnclaveClient client;
    private final List<byte[]> keys;
    private final long[] latencies;
    private final Sample[] samples;
    private final AtomicInteger failures = new AtomicInteger();
    private final AtomicReference<RuntimeException> firstFailure = new AtomicReference<>();

    Calls(final EnclaveClient client, final List<byte[]> keys, final int requests) {
      this.client = client;
      this.keys = keys;
      this.latencies = new long[requests];
      this.samples = new Sample[Math.min(VERIFIED_SIGNATURES, requests)];
    }

    void signOnce(final int index) {
      final byte[] message = new byte[32];
      ThreadLocalRandom.current().nextBytes(message);
      final byte[] publicKey = keys.get(ThreadLocalRandom.current().nextInt(keys.size()));
      final long begin = System.nanoTime();
      try {
        final byte[] signature = client.sign(publicKey, message);
        latencies[index] = System.nanoTime() - begin;
        if (index < samples.length) {
          samples[index] = new Sample(publicKey, message, signature);
        }
      } catch (final RuntimeException e) {
        latencies[index] = FAILED;
        failures.incrementAndGet();
        firstFailure.compareAndSet(null, e);
      }
    }

    long[] succeededSorted() {
      return Arrays.stream(latencies).filter(latency -> latency != FAILED).sorted().toArray();
    }
  }

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

    final Calls calls = new Calls(client, keys, options.requests());
    final long start = System.nanoTime();
    try (ExecutorService pool = Executors.newFixedThreadPool(options.callers())) {
      for (int i = 0; i < options.requests(); i++) {
        final int index = i;
        pool.execute(() -> calls.signOnce(index));
      }
    }
    if (Thread.interrupted()) {
      throw new InterruptedException();
    }
    final double seconds = (System.nanoTime() - start) / 1e9;

    final int verifyFailures =
        options.verify()
            ? (int)
                Arrays.stream(calls.samples)
                    .filter(Objects::nonNull)
                    .filter(sample -> !verifies(sample))
                    .count()
            : 0;
    final long[] succeeded = calls.succeededSorted();
    final Result result =
        new Result(
            succeeded.length / seconds,
            percentile(succeeded, 0.50),
            percentile(succeeded, 0.95),
            percentile(succeeded, 0.99),
            baseline,
            calls.failures.get(),
            verifyFailures);
    if (succeeded.length > 0) {
      out.printf(
          Locale.ROOT,
          "%.0f signs/s, p50 %.0f us, p95 %.0f us, p99 %.0f us%n",
          result.signsPerSecond(),
          result.p50(),
          result.p95(),
          result.p99());
    } else {
      out.printf(Locale.ROOT, "no call succeeded%n");
    }
    if (result.failures() > 0) {
      out.printf(
          Locale.ROOT,
          "%d calls failed, first: %s%n",
          result.failures(),
          calls.firstFailure.get().getMessage());
    }
    if (options.verify()) {
      out.printf(
          Locale.ROOT,
          "verified %d signatures, %d mismatches%n",
          Arrays.stream(calls.samples).filter(Objects::nonNull).count(),
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
    if (sortedNanos.length == 0) {
      return Double.NaN;
    }
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
