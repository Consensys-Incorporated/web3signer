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
package tech.pegasys.web3signer.enclave.transport;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;

/**
 * A blocking byte stream to or from an enclave signer. One thread at a time reads and writes;
 * {@link #close()} may come from any thread. A read timeout surfaces as {@link
 * java.net.SocketTimeoutException}.
 */
public interface Connection extends Closeable {

  /**
   * Reads at least one byte, blocking until some are available.
   *
   * @return the number of bytes read, or -1 at the end of the stream
   */
  int read(byte[] buffer, int offset, int length) throws IOException;

  /** Writes all bytes, as one write to the transport where it allows. */
  void write(byte[] buffer, int offset, int length) throws IOException;

  /** Reads exactly {@code length} bytes. Throws {@link EOFException} at the end of the stream. */
  default void readFully(final byte[] buffer, final int offset, final int length)
      throws IOException {
    int done = 0;
    while (done < length) {
      final int n = read(buffer, offset + done, length - done);
      if (n < 0) {
        throw new EOFException("Connection closed by peer");
      }
      done += n;
    }
  }

  /** Closes the connection. Never throws. */
  @Override
  void close();
}
