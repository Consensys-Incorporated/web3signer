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

/** Constants of the enclave signer wire protocol, version 1. All integers are big-endian. */
public final class Protocol {
  public static final int VERSION = 1;

  // Opcodes. A response carries the opcode with RESPONSE_FLAG set.
  public static final int STATUS = 0x01;
  public static final int GET_PUBLIC_KEYS = 0x02;
  public static final int SIGN = 0x03;
  public static final int ATTEST = 0x10;
  public static final int UNWRAP_DEK = 0x11;
  public static final int LOAD_KEYS = 0x12;
  public static final int RESPONSE_FLAG = 0x80;

  // Status codes, the first payload byte of every response
  public static final int OK = 0;
  public static final int BAD_REQUEST = 1;
  public static final int UNSUPPORTED = 2;
  public static final int UNKNOWN_KEY = 3;
  public static final int INVALID_STATE = 4;
  public static final int UNWRAP_FAILED = 5;
  public static final int ATTESTATION_FAILED = 6;
  public static final int INTERNAL_ERROR = 7;

  // Platforms reported by STATUS
  public static final int PLATFORM_DEV = 0;
  public static final int PLATFORM_AWS_NITRO = 1;

  /** Release blob format 1: the CMS EnvelopedData that AWS KMS returns for a recipient. */
  public static final int BLOB_FORMAT_CMS = 1;

  // Frame: length u32, then type u8, request_id u32, payload
  public static final int LENGTH_PREFIX_SIZE = 4;
  public static final int FRAME_HEADER_SIZE = 5;
  public static final int MIN_FRAME_LENGTH = FRAME_HEADER_SIZE;
  public static final int MAX_FRAME_LENGTH = 1_048_576;
  public static final int MAX_PAYLOAD_SIZE = MAX_FRAME_LENGTH - FRAME_HEADER_SIZE;

  // Field sizes and ranges
  public static final int PUBLIC_KEY_SIZE = 48;
  public static final int SIGNATURE_SIZE = 96;
  public static final int SECRET_KEY_SIZE = 32;
  public static final int DEK_SIZE = 32;
  public static final int BOOT_ID_SIZE = 16;
  public static final int MAX_MESSAGE_SIZE = 65_535;
  public static final int MAX_NONCE_SIZE = 64;
  public static final int MAX_PUBLIC_KEYS_PAGE = 16_384;
  public static final int MAX_LOAD_KEYS = 4096;
  public static final int SEALED_NONCE_SIZE = 12;
  public static final int SEALED_CIPHERTEXT_SIZE = 48;
  public static final int SEALED_KEY_SIZE =
      PUBLIC_KEY_SIZE + SEALED_NONCE_SIZE + SEALED_CIPHERTEXT_SIZE;

  private Protocol() {}

  public static String statusName(final int status) {
    return switch (status) {
      case OK -> "OK";
      case BAD_REQUEST -> "BAD_REQUEST";
      case UNSUPPORTED -> "UNSUPPORTED";
      case UNKNOWN_KEY -> "UNKNOWN_KEY";
      case INVALID_STATE -> "INVALID_STATE";
      case UNWRAP_FAILED -> "UNWRAP_FAILED";
      case ATTESTATION_FAILED -> "ATTESTATION_FAILED";
      case INTERNAL_ERROR -> "INTERNAL_ERROR";
      default -> "STATUS_" + status;
    };
  }

  public static String platformName(final int platform) {
    return switch (platform) {
      case PLATFORM_DEV -> "dev";
      case PLATFORM_AWS_NITRO -> "aws-nitro";
      default -> "platform-" + platform;
    };
  }

  /** Parses a platform name as used on command lines: {@code dev} or {@code aws-nitro}. */
  public static int parsePlatform(final String name) {
    return switch (name) {
      case "dev" -> PLATFORM_DEV;
      case "aws-nitro" -> PLATFORM_AWS_NITRO;
      default -> throw new IllegalArgumentException("Unknown platform: " + name);
    };
  }
}
