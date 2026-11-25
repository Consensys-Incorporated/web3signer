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

/** Constants of the enclave signer wire protocol, version 1. */
public final class Protocol {
  public static final int VERSION = 1;

  // Opcodes: the kind of a request frame
  public static final int STATUS = 0x01;
  public static final int GET_PUBLIC_KEYS = 0x02;
  public static final int SIGN = 0x03;
  public static final int GET_EVIDENCE = 0x10;
  public static final int UNWRAP_DEK = 0x11;
  public static final int LOAD_KEYS = 0x12;

  // Result codes: the kind of a response frame. 0 to 3 keep their meaning from the consensus
  // req/resp protocol (Success, InvalidRequest, ServerError, ResourceUnavailable); our own codes
  // start at 128.
  public static final int OK = 0;
  public static final int BAD_REQUEST = 1;
  public static final int INTERNAL_ERROR = 2;

  /** The enclave does not hold the key a {@code SIGN} asked for. */
  public static final int RESOURCE_UNAVAILABLE = 3;

  public static final int UNSUPPORTED = 128;
  public static final int INVALID_STATE = 129;
  public static final int UNWRAP_FAILED = 130;
  public static final int EVIDENCE_FAILED = 131;

  // Platforms reported by STATUS
  public static final int PLATFORM_DEV = 0;
  public static final int PLATFORM_AWS_NITRO = 1;

  // Evidence types of GET_EVIDENCE
  /** Evidence of the dev platform: no hardware root of trust. */
  public static final int EVIDENCE_DEV = 0;

  /** An AWS Nitro attestation document (COSE_Sign1) whose public key is the release key. */
  public static final int EVIDENCE_AWS_NITRO = 1;

  /** Release blob format 1: the CMS EnvelopedData that AWS KMS returns for a recipient. */
  public static final int BLOB_FORMAT_CMS = 1;

  /** Largest frame body. */
  public static final int MAX_BODY_SIZE = 1_048_576;

  // Field sizes and limits
  public static final int PUBLIC_KEY_SIZE = 48;
  public static final int SIGNING_ROOT_SIZE = 32;
  public static final int SIGNATURE_SIZE = 96;
  public static final int SECRET_KEY_SIZE = 32;
  public static final int DEK_SIZE = 32;
  public static final int BOOT_ID_SIZE = 16;
  public static final int MAX_VERSION_SIZE = 256;
  public static final int MAX_ERROR_MESSAGE_SIZE = 256;
  public static final int MAX_NONCE_SIZE = 64;
  public static final int MAX_RELEASE_KEY_SIZE = 2048;
  public static final int MAX_EVIDENCE_SIZE = 65_536;
  public static final int MAX_BLOB_SIZE = 65_536;
  public static final int MAX_PUBLIC_KEYS_PAGE = 16_384;
  public static final int MAX_LOAD_KEYS = 4096;
  public static final int SEALED_NONCE_SIZE = 12;
  public static final int SEALED_CIPHERTEXT_SIZE = 48;
  public static final int SEALED_KEY_SIZE =
      PUBLIC_KEY_SIZE + SEALED_NONCE_SIZE + SEALED_CIPHERTEXT_SIZE;

  private Protocol() {}

  public static String opcodeName(final int opcode) {
    return switch (opcode) {
      case STATUS -> "STATUS";
      case GET_PUBLIC_KEYS -> "GET_PUBLIC_KEYS";
      case SIGN -> "SIGN";
      case GET_EVIDENCE -> "GET_EVIDENCE";
      case UNWRAP_DEK -> "UNWRAP_DEK";
      case LOAD_KEYS -> "LOAD_KEYS";
      default -> "OPCODE_0x" + Integer.toHexString(opcode);
    };
  }

  public static String resultName(final int result) {
    return switch (result) {
      case OK -> "OK";
      case BAD_REQUEST -> "BAD_REQUEST";
      case INTERNAL_ERROR -> "INTERNAL_ERROR";
      case RESOURCE_UNAVAILABLE -> "RESOURCE_UNAVAILABLE";
      case UNSUPPORTED -> "UNSUPPORTED";
      case INVALID_STATE -> "INVALID_STATE";
      case UNWRAP_FAILED -> "UNWRAP_FAILED";
      case EVIDENCE_FAILED -> "EVIDENCE_FAILED";
      default -> "RESULT_" + result;
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
