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
package tech.pegasys.web3signer.keystorage.postgres.crypto;

import java.util.Arrays;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A reference-counted holder for a decrypted tenant DEK, allowing it to be safely wiped once
 * evicted from the cache without racing a concurrent decrypt operation.
 *
 * <p>Caffeine's removal listener runs on a maintenance thread with no relationship to whether a
 * decrypt thread is mid-operation holding this exact byte array - directly zeroing the array in the
 * removal listener risks a concurrent thread observing a partially-wiped key. Instead, callers take
 * a short-lived read-lock {@link Lease} to use the key bytes; eviction/rotation/shutdown marks this
 * instance for wipe and attempts a non-blocking write-lock, which only succeeds once every
 * outstanding lease has been closed. Since no new leases can be acquired once a wipe has been
 * requested (see {@link #acquireForRead()}), the outstanding-lease count is monotonically
 * decreasing and the wipe is guaranteed to eventually succeed.
 */
public final class TenantDek {

  private final byte[] keyBytes;
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private volatile boolean pendingWipe = false;
  private volatile boolean wiped = false;

  public TenantDek(final byte[] keyBytes) {
    this.keyBytes = keyBytes;
  }

  public Lease acquireForRead() {
    lock.readLock().lock();
    try {
      if (pendingWipe || wiped) {
        throw new IllegalStateException("TenantDek has been invalidated and can no longer be used");
      }
      return new Lease();
    } catch (final RuntimeException e) {
      lock.readLock().unlock();
      throw e;
    }
  }

  /** Marks this DEK for wipe and attempts it immediately; safe to call more than once. */
  public void markForWipeAndAttempt() {
    pendingWipe = true;
    attemptWipe();
  }

  private void attemptWipe() {
    if (wiped) {
      return;
    }
    if (lock.writeLock().tryLock()) {
      try {
        if (!wiped) {
          Arrays.fill(keyBytes, (byte) 0);
          wiped = true;
        }
      } finally {
        lock.writeLock().unlock();
      }
    }
    // else: readers still active - the next Lease#close() retries the wipe.
  }

  public final class Lease implements AutoCloseable {

    public byte[] keyBytes() {
      return keyBytes;
    }

    @Override
    public void close() {
      lock.readLock().unlock();
      if (pendingWipe) {
        attemptWipe();
      }
    }
  }
}
