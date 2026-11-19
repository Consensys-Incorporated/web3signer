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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/** The blst native library from the jblst jar on the test classpath, copied to a temp file. */
public final class BlstTestLibrary {
  private static Path path;

  private BlstTestLibrary() {}

  public static synchronized Path path() {
    if (path == null) {
      final String resource = "/supranational/blst/" + platformDirectory() + "/" + libraryName();
      try (InputStream in = BlstTestLibrary.class.getResourceAsStream(resource)) {
        if (in == null) {
          throw new IllegalStateException("jblst library not on the classpath: " + resource);
        }
        final Path file = Files.createTempFile("blst", libraryName());
        file.toFile().deleteOnExit();
        Files.copy(in, file, StandardCopyOption.REPLACE_EXISTING);
        path = file;
      } catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
    }
    return path;
  }

  private static boolean isMac() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac");
  }

  private static String platformDirectory() {
    final String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
    final boolean arm = arch.equals("aarch64") || arch.equals("arm64");
    if (isMac()) {
      return arm ? "Mac/aarch64" : "Mac/x86_64";
    }
    return arm ? "Linux/aarch64" : "Linux/amd64";
  }

  private static String libraryName() {
    return isMac() ? "libblst.dylib" : "libblst.so";
  }
}
