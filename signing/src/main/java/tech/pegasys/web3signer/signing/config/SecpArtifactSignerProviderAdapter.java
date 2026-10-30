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
package tech.pegasys.web3signer.signing.config;

import static org.web3j.crypto.Keys.getAddress;
import static tech.pegasys.web3signer.signing.util.IdentifierUtils.normaliseIdentifier;

import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Thread-safe adapter that provides Ethereum address-based access to secp256k1 artifact signers.
 *
 * <p>This adapter wraps an existing {@link ArtifactSignerProvider} and translates secp256k1 public
 * key identifiers to their corresponding Ethereum (eth1) addresses. This allows signers to be
 * looked up by address rather than by public key.
 *
 * <h2>Thread Safety</h2>
 *
 * This class uses a copy-on-write strategy with a volatile immutable map to ensure thread-safe
 * reads without locking. The {@link #load()} method atomically replaces the entire signer map,
 * allowing concurrent reads during updates.
 *
 * <h2>Limitations</h2>
 *
 * <ul>
 *   <li>The {@link #load()} method assumes the underlying provider has already loaded its signers
 *   <li>Signer addition and removal operations are not supported (throw {@link
 *       NotImplementedException})
 *   <li>Only works with secp256k1 signers that can be mapped to Ethereum addresses
 * </ul>
 *
 * * @see ArtifactSignerProvider
 */
public class SecpArtifactSignerProviderAdapter implements ArtifactSignerProvider {
  private static final Logger LOG = LogManager.getLogger();
  private final ExecutorService executorService = Executors.newSingleThreadExecutor();
  // volatile reference with immutable map with copy-on-write
  private volatile Map<String, ArtifactSigner> signers = Map.of();
  private final ArtifactSignerProvider signerProvider;

  public SecpArtifactSignerProviderAdapter(final ArtifactSignerProvider signerProvider) {
    this.signerProvider = signerProvider;
  }

  /**
   * Maps loaded signers to their Ethereum (eth1) address identifiers.
   *
   * <p>This adapter does not perform actual signer loading - it assumes the underlying {@code
   * signerProvider} has already completed its load operation. This method:
   *
   * <ol>
   *   <li>Retrieves all available identifiers from the underlying provider
   *   <li>Maps each secp256k1 public key to its corresponding Ethereum address
   *   <li>Populates the internal map for address-based lookups
   * </ol>
   *
   * <p><b>Important:</b> This method should be called <em>after</em> the underlying {@code
   * signerProvider.load()} has completed, as it relies on signers already being available.
   *
   * <p>Since this is a mapping operation rather than loading from external sources, it always
   * returns an error count of 0. Any errors from the underlying provider's load operation are not
   * reflected in this adapter's error count.
   *
   * @return a {@link Future} containing 0, as this operation performs mapping rather than loading
   *     and does not encounter signer loading errors
   */
  @Override
  public Future<Long> load() {
    return executorService.submit(
        () -> {
          LOG.debug("Adding eth1 address for eth1 keys");
          // this assumes that signerProvider.load() has already been executed
          signers =
              signerProvider.availableIdentifiers().stream()
                  .flatMap(
                      publicKey ->
                          signerProvider.getSigner(publicKey).stream()
                              .map(
                                  signer ->
                                      Map.entry(
                                          normaliseIdentifier(getAddress(publicKey)), signer)))
                  .collect(
                      Collectors.toUnmodifiableMap(
                          Map.Entry::getKey,
                          Map.Entry::getValue,
                          (existing, replacement) -> existing));

          return 0L; // no error, since its a mapping method
        });
  }

  @Override
  public Optional<ArtifactSigner> getSigner(final String eth1Address) {
    return Optional.ofNullable(signers.get(eth1Address));
  }

  @Override
  public Set<String> availableIdentifiers() {
    return signers.keySet(); // immutable view
  }

  @Override
  public Future<Void> addSigner(final ArtifactSigner signer, final Optional<Path> keyConfigFile) {
    throw new NotImplementedException();
  }

  @Override
  public Future<Void> removeSigner(final String eth1Address) {
    throw new NotImplementedException();
  }

  @Override
  public void close() {
    executorService.shutdownNow();
  }
}
