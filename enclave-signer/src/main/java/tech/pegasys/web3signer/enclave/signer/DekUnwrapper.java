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

import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Opens the release blob (format 1) with the enclave's one-time RSA key.
 *
 * <p>The content is decrypted with {@code AES/CBC/NoPadding} and must be exactly 48 bytes; the data
 * key is the first 32. The padding block is never inspected, and every failure surfaces as the same
 * {@link UnwrapException} without detail: the parent carries the blob and could otherwise use the
 * enclave as a padding oracle.
 */
final class DekUnwrapper {
  private static final int CONTENT_SIZE = 48;

  private DekUnwrapper() {}

  /** Any failure while unwrapping. Deliberately carries no detail and no cause. */
  static final class UnwrapException extends Exception {
    private static final long serialVersionUID = 1L;

    UnwrapException() {
      super("unwrap failed");
    }
  }

  /** Returns the 32-byte data key. */
  static byte[] unwrap(final PrivateKey rsaKey, final byte[] blob) throws UnwrapException {
    byte[] contentKey = null;
    byte[] content = null;
    try {
      final CmsEnvelopedData envelope = CmsEnvelopedData.parse(blob);
      if (envelope.encryptedContent().length != CONTENT_SIZE) {
        throw new UnwrapException();
      }
      final Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPPadding");
      oaep.init(
          Cipher.DECRYPT_MODE,
          rsaKey,
          new OAEPParameterSpec(
              "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
      contentKey = oaep.doFinal(envelope.encryptedKey());
      if (contentKey.length != 32) {
        throw new UnwrapException();
      }
      final Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
      aes.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(contentKey, "AES"),
          new IvParameterSpec(envelope.iv()));
      content = aes.doFinal(envelope.encryptedContent());
      return Arrays.copyOf(content, Protocol.DEK_SIZE);
    } catch (final Exception e) {
      throw new UnwrapException();
    } finally {
      if (contentKey != null) {
        Arrays.fill(contentKey, (byte) 0);
      }
      if (content != null) {
        Arrays.fill(content, (byte) 0);
      }
    }
  }
}
