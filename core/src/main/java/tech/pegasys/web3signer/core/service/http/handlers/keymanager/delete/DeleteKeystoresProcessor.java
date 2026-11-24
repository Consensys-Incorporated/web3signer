/*
 * Copyright 2022 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete;

import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.ValidatorManager;
import tech.pegasys.web3signer.signing.util.IdentifierUtils;
import tech.pegasys.web3signer.slashingprotection.SlashingProtection;
import tech.pegasys.web3signer.slashingprotection.interchange.EmptyDataIncrementalInterchangeV5Exporter;
import tech.pegasys.web3signer.slashingprotection.interchange.IncrementalExporter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class DeleteKeystoresProcessor {

  private static final Logger LOG = LogManager.getLogger();

  private final Optional<SlashingProtection> slashingProtection;
  private final ArtifactSignerProvider signerProvider;
  private final ValidatorManager validatorManager;

  public DeleteKeystoresProcessor(
      final Optional<SlashingProtection> slashingProtection,
      final ArtifactSignerProvider signerProvider,
      final ValidatorManager validatorManager) {
    this.slashingProtection = slashingProtection;
    this.signerProvider = signerProvider;
    this.validatorManager = validatorManager;
  }

  public DeleteKeystoresResponse process(final DeleteKeystoresRequestBody requestBody) {
    final List<DeleteKeystoreResult> results = new ArrayList<>();
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    try (final IncrementalExporter incrementalExporter = createIncrementalExporter(outputStream)) {
      // normalize incoming keys to delete
      final List<String> pubkeysToDelete =
          requestBody.getPubkeys().stream()
              .map(IdentifierUtils::normaliseIdentifier)
              .collect(Collectors.toList());

      for (String pubkey : pubkeysToDelete) {
        results.add(processKeyToDelete(pubkey, incrementalExporter));
      }

      try {
        incrementalExporter.finalise();
      } catch (IOException ioException) {
        LOG.error("Failed to export slashing data", ioException);
        setAllResultsToError(results, ioException);
      }
    } catch (Exception e) {
      // Any unhandled error we want to bubble up so that we return an internal error response
      throw new RuntimeException("Error deleting keystores", e);
    }

    final String slashingProtectionExport = outputStream.toString(StandardCharsets.UTF_8);
    return new DeleteKeystoresResponse(results, slashingProtectionExport);
  }

  private void setAllResultsToError(
      final List<DeleteKeystoreResult> results, final IOException ioException) {
    final List<DeleteKeystoreResult> errorResults =
        results.stream()
            .map(
                result ->
                    new DeleteKeystoreResult(
                        DeleteKeystoreStatus.ERROR,
                        "Error exporting slashing data: " + ioException.getMessage()))
            .collect(Collectors.toList());
    results.clear();
    results.addAll(errorResults);
  }

  private IncrementalExporter createIncrementalExporter(final OutputStream outputStream) {
    return slashingProtection
        .map(sp -> sp.createIncrementalExporter(outputStream))
        // nothing to export if slashing protection is not available, hence use no-op exporter so
        // that outputStream can be closed nicely.
        .orElseGet(() -> new EmptyDataIncrementalInterchangeV5Exporter(outputStream));
  }

  private DeleteKeystoreResult processKeyToDelete(
      final String pubkey, final IncrementalExporter incrementalExporter) {
    try {
      final Optional<ArtifactSigner> signer = signerProvider.getSigner(pubkey);

      // check that key is active
      if (signer.isEmpty()) {
        final boolean slashingProtectionDataExistsForPubKey =
            slashingProtection
                .map(sp -> sp.hasSlashingProtectionDataFor(Bytes.fromHexString(pubkey)))
                .orElse(false);

        if (slashingProtectionDataExistsForPubKey) {
          return attemptToExportWithSlashingData(
              pubkey, incrementalExporter, DeleteKeystoreStatus.NOT_ACTIVE);
        } else {
          return new DeleteKeystoreResult(DeleteKeystoreStatus.NOT_FOUND, "");
        }
      }

      // Check that key is read only, if so return an error status. Only BLS keys loaded from
      // keystore files are editable; every other signer, enclave keys included, is read only.
      if (!(signer.get() instanceof BlsArtifactSigner blsSigner) || blsSigner.isReadOnlyKey()) {
        return new DeleteKeystoreResult(
            DeleteKeystoreStatus.ERROR, "Unable to delete readonly key: " + pubkey);
      }

      validatorManager.deleteValidator(Bytes.fromHexString(pubkey));
    } catch (Exception e) {
      LOG.error("Failed to delete keystore files", e);
      return new DeleteKeystoreResult(
          DeleteKeystoreStatus.ERROR, "Error deleting keystore file: " + e.getMessage());
    }

    return attemptToExportWithSlashingData(
        pubkey, incrementalExporter, DeleteKeystoreStatus.DELETED);
  }

  private DeleteKeystoreResult attemptToExportWithSlashingData(
      final String pubkey,
      final IncrementalExporter incrementalExporter,
      final DeleteKeystoreStatus status) {
    try {
      incrementalExporter.export(pubkey);
      return new DeleteKeystoreResult(status, "");
    } catch (Exception e) {
      LOG.error("Failed to export slashing data for public key {}", pubkey, e);
      return new DeleteKeystoreResult(
          DeleteKeystoreStatus.ERROR, "Error exporting slashing data: " + e.getMessage());
    }
  }
}
