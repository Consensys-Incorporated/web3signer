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

import java.io.IOException;

/**
 * Address of an enclave signer.
 *
 * <p>Connect forms: {@code vsock:<cid>:<port>} and {@code tcp:<host>:<port>}. Listen forms: {@code
 * vsock:<port>} (any CID) and {@code tcp:<host>:<port>}.
 */
public sealed interface EnclaveAddress
    permits EnclaveAddress.VsockAddress, EnclaveAddress.TcpAddress {
  long VMADDR_CID_ANY = 0xFFFF_FFFFL;
  long VMADDR_PORT_ANY = 0xFFFF_FFFFL;

  /**
   * Connects to this address.
   *
   * @param connectTimeoutMillis connect timeout; 0 waits forever on TCP and keeps the kernel's
   *     default of 2 s on vsock
   * @param ioTimeoutMillis read and write timeout; 0 waits forever
   */
  Connection connect(int connectTimeoutMillis, int ioTimeoutMillis) throws IOException;

  /** Listens on this address. */
  Listener listen() throws IOException;

  /**
   * A vsock address.
   *
   * @param cid the context id as an unsigned 32-bit value, {@link #VMADDR_CID_ANY} to listen
   * @param port the port, an unsigned 32-bit value
   */
  record VsockAddress(long cid, long port) implements EnclaveAddress {
    public VsockAddress {
      checkU32(cid, "CID");
      checkU32(port, "port");
    }

    // connect and listen cast to int, so a wider value would reach another CID or port
    private static void checkU32(final long value, final String name) {
      if ((value >>> 32) != 0) {
        throw new IllegalArgumentException("vsock " + name + " out of range: " + value);
      }
    }

    @Override
    public Connection connect(final int connectTimeoutMillis, final int ioTimeoutMillis)
        throws IOException {
      return Vsock.connect((int) cid, (int) port, connectTimeoutMillis, ioTimeoutMillis);
    }

    @Override
    public Listener listen() throws IOException {
      return Vsock.listen((int) port);
    }

    @Override
    public String toString() {
      return cid == VMADDR_CID_ANY ? "vsock:" + port : "vsock:" + cid + ":" + port;
    }
  }

  /**
   * A TCP address.
   *
   * @param host host name or IP address, without brackets
   * @param port 0 to 65535; 0 listens on a free port
   */
  record TcpAddress(String host, int port) implements EnclaveAddress {
    @Override
    public Connection connect(final int connectTimeoutMillis, final int ioTimeoutMillis)
        throws IOException {
      return Tcp.connect(host, port, connectTimeoutMillis, ioTimeoutMillis);
    }

    @Override
    public Listener listen() throws IOException {
      return Tcp.listen(host, port);
    }

    @Override
    public String toString() {
      return host.contains(":") ? "tcp:[" + host + "]:" + port : "tcp:" + host + ":" + port;
    }
  }

  static EnclaveAddress vsock(final long cid, final long port) {
    return new VsockAddress(cid, port);
  }

  static EnclaveAddress tcp(final String host, final int port) {
    return new TcpAddress(host, port);
  }

  /**
   * Parses an address to connect to. A vsock CID must name a guest: 0 (hypervisor), 1 (local), 2
   * (host) and {@link #VMADDR_CID_ANY} (listen only) are rejected.
   */
  static EnclaveAddress parseConnect(final String value) {
    if (value != null && value.startsWith("vsock:")) {
      final String[] parts = value.substring("vsock:".length()).split(":", -1);
      if (parts.length != 2) {
        throw invalid(value, "expected vsock:<cid>:<port>");
      }
      final long cid = u32(value, parts[0]);
      if (cid <= 2 || cid == VMADDR_CID_ANY) {
        throw invalid(value, "CID " + cid + " does not name an enclave");
      }
      return vsock(cid, u32(value, parts[1]));
    }
    return parseTcp(value, false);
  }

  /** Parses an address to listen on. {@link #VMADDR_PORT_ANY} is rejected. */
  static EnclaveAddress parseListen(final String value) {
    if (value != null && value.startsWith("vsock:")) {
      final String port = value.substring("vsock:".length());
      if (port.contains(":")) {
        throw invalid(value, "expected vsock:<port>");
      }
      final long number = u32(value, port);
      // the kernel would bind a random port, which address() could not report
      if (number == VMADDR_PORT_ANY) {
        throw invalid(value, "port " + number + " means any port");
      }
      // unlike TCP, port 0 is an ordinary (privileged) vsock port
      if (number == 0) {
        throw invalid(value, "port 0 does not mean any port on vsock");
      }
      return vsock(VMADDR_CID_ANY, number);
    }
    return parseTcp(value, true);
  }

  private static EnclaveAddress parseTcp(final String value, final boolean listen) {
    if (value == null || !value.startsWith("tcp:")) {
      throw invalid(value, "expected a vsock: or tcp: address");
    }
    final String rest = value.substring("tcp:".length());
    final int colon = rest.lastIndexOf(':');
    if (colon <= 0) {
      throw invalid(value, "expected tcp:<host>:<port>");
    }
    String host = rest.substring(0, colon);
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    } else if (host.contains(":")) {
      throw invalid(value, "an IPv6 host needs brackets, e.g. tcp:[::1]:<port>");
    }
    if (host.isEmpty() || host.chars().anyMatch(Character::isWhitespace)) {
      throw invalid(value, "invalid host");
    }
    final long port = u32(value, rest.substring(colon + 1));
    if (port > 65_535 || (!listen && port == 0)) {
      throw invalid(value, "invalid TCP port");
    }
    return tcp(host, (int) port);
  }

  private static long u32(final String value, final String digits) {
    if (!digits.matches("[0-9]{1,10}") || Long.parseLong(digits) > 0xFFFF_FFFFL) {
      throw invalid(value, "invalid number '" + digits + "'");
    }
    return Long.parseLong(digits);
  }

  private static IllegalArgumentException invalid(final String value, final String reason) {
    return new IllegalArgumentException("Invalid enclave address '" + value + "': " + reason);
  }
}
