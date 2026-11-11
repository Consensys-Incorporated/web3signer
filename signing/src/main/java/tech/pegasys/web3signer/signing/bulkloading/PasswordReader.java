/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.signing.bulkloading;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;

@FunctionalInterface
public interface PasswordReader {
  String readPassword(final String fileName) throws IOException;

  /**
   * Reads each password from its own file in {@code passwordsDirectory}.
   *
   * @throws IOException if the directory is missing, is not a directory or cannot be listed, so
   *     that the caller reports a source failure instead of one failed file per keystore
   */
  static PasswordReader fromDirectory(final Path passwordsDirectory) throws IOException {
    try (final DirectoryStream<Path> ignored = Files.newDirectoryStream(passwordsDirectory)) {
      return fileName -> Files.readString(passwordsDirectory.resolve(fileName));
    }
  }
}
