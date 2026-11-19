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
 * Address of an enclave signer.
 *
 * <p>Connect forms: {@code vsock:<cid>:<port>} and {@code tcp:<host>:<port>}. Listen forms: {@code
 * vsock:<port>} (any CID) and {@code tcp:<host>:<port>}.
 *
 * @param kind the transport
 * @param host the TCP host, null for vsock
 * @param cid the vsock context id as an unsigned 32-bit value, {@link #VMADDR_CID_ANY} for a vsock
 *     listen address, 0 for TCP
 * @param port the port: 0 to 65535 for TCP, an unsigned 32-bit value for vsock
 */
public record EnclaveAddress(Kind kind, String host, long cid, long port) {
  public static final long VMADDR_CID_ANY = 0xFFFF_FFFFL;
  private static final long U32_MAX = 0xFFFF_FFFFL;

  /** Transport kinds. */
  public enum Kind {
    VSOCK,
    TCP
  }

  public static EnclaveAddress vsock(final long cid, final long port) {
    return new EnclaveAddress(Kind.VSOCK, null, cid, port);
  }

  public static EnclaveAddress tcp(final String host, final int port) {
    return new EnclaveAddress(Kind.TCP, host, 0, port);
  }

  /** Parses an address to connect to. */
  public static EnclaveAddress parseConnect(final String value) {
    if (value != null && value.startsWith("vsock:")) {
      final String[] parts = value.substring("vsock:".length()).split(":", -1);
      if (parts.length != 2) {
        throw invalid(value, "expected vsock:<cid>:<port>");
      }
      return vsock(u32(value, parts[0]), u32(value, parts[1]));
    }
    return parseTcp(value, false);
  }

  /** Parses an address to listen on. */
  public static EnclaveAddress parseListen(final String value) {
    if (value != null && value.startsWith("vsock:")) {
      final String port = value.substring("vsock:".length());
      if (port.contains(":")) {
        throw invalid(value, "expected vsock:<port>");
      }
      return vsock(VMADDR_CID_ANY, u32(value, port));
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
    if (digits.isEmpty() || digits.length() > 10 || !digits.chars().allMatch(Character::isDigit)) {
      throw invalid(value, "invalid number '" + digits + "'");
    }
    final long result = Long.parseLong(digits);
    if (result > U32_MAX) {
      throw invalid(value, "number out of range '" + digits + "'");
    }
    return result;
  }

  private static IllegalArgumentException invalid(final String value, final String reason) {
    return new IllegalArgumentException("Invalid enclave address '" + value + "': " + reason);
  }

  @Override
  public String toString() {
    if (kind == Kind.VSOCK) {
      return cid == VMADDR_CID_ANY ? "vsock:" + port : "vsock:" + cid + ":" + port;
    }
    return host.contains(":") ? "tcp:[" + host + "]:" + port : "tcp:" + host + ":" + port;
  }
}
