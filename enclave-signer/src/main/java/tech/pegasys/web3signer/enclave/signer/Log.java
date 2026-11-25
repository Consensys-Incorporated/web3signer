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
package tech.pegasys.web3signer.enclave.signer;

import java.time.Instant;

/**
 * Timestamped lines on {@code System.err}. Callers log counts and error classes only, never a
 * payload, a key or a data key.
 */
public final class Log {
  private Log() {}

  public static void info(final String message) {
    System.err.println(Instant.now() + " INFO " + message);
  }

  public static void warn(final String message) {
    System.err.println(Instant.now() + " WARN " + message);
  }

  /** Logs the class of {@code error} only: messages of crypto exceptions can carry data. */
  public static void error(final String message, final Throwable error) {
    System.err.println(Instant.now() + " ERROR " + message + ": " + error.getClass().getName());
  }
}
