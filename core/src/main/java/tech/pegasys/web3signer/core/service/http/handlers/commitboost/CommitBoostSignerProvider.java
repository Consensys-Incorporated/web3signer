/*
 * Copyright 2024 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.http.handlers.commitboost;

import tech.pegasys.web3signer.core.service.http.handlers.commitboost.json.CommitBoostSignRequestType;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;

import java.nio.file.Path;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;

/**
 * This class wraps the {@link ArtifactSignerProvider} and provides a way to check if a signer is
 * available, consensus or proxy,and to sign a message.
 */
public class CommitBoostSignerProvider {
  private final ArtifactSignerProvider artifactSignerProvider;

  /**
   * Constructor for the CommitBoostSignerProvider
   *
   * @param artifactSignerProvider The {@link ArtifactSignerProvider} to use for signing
   */
  public CommitBoostSignerProvider(final ArtifactSignerProvider artifactSignerProvider) {
    this.artifactSignerProvider = artifactSignerProvider;
  }

  /**
   * Check if a signer is available for the given identifier and type
   *
   * @param identifier The identifier to check
   * @param type The type of signer to check
   * @return true if a signer is available, false otherwise
   */
  public boolean isSignerAvailable(final String identifier, final CommitBoostSignRequestType type) {
    return switch (type) {
      case CONSENSUS -> artifactSignerProvider.availableIdentifiers().contains(identifier);
      case PROXY_BLS, PROXY_ECDSA -> artifactSignerProvider.getProxySigner(identifier).isPresent();
    };
  }

  /**
   * Sign a message with the given identifier and type
   *
   * @param identifier The identifier to sign with
   * @param type The type of signer to use
   * @param signingRoot The root to sign
   * @return An optional string of the signature in hex format. Empty if no signer available for
   *     given identifier
   */
  public Optional<String> sign(
      final String identifier, final CommitBoostSignRequestType type, final Bytes32 signingRoot) {
    final Optional<ArtifactSigner> optionalArtifactSigner =
        type == CommitBoostSignRequestType.CONSENSUS
            ? artifactSignerProvider.getSigner(identifier)
            : artifactSignerProvider.getProxySigner(identifier);

    return optionalArtifactSigner.map(signer -> signer.sign(signingRoot).asHex());
  }

  /**
   * Add a proxy signer to the consensus signer
   *
   * @param proxySigner The proxy signer to add
   * @param consensusPubKey The consensus public key to associate with the proxy signer
   * @param keystoreFile The proxy keystore file written for the proxy signer
   */
  public void addProxySigner(
      final ArtifactSigner proxySigner, final String consensusPubKey, final Path keystoreFile) {
    artifactSignerProvider.addProxySigner(proxySigner, consensusPubKey, keystoreFile);
  }
}
