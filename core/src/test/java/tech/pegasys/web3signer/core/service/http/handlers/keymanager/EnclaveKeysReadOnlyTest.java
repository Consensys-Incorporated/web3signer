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
package tech.pegasys.web3signer.core.service.http.handlers.keymanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete.DeleteKeystoreStatus;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete.DeleteKeystoresProcessor;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete.DeleteKeystoresRequestBody;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.delete.DeleteKeystoresResponse;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.list.ListKeystoresHandler;
import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.host.EnclaveTestKeys;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.BlsArtifactSignature;
import tech.pegasys.web3signer.signing.EnclaveBlsArtifactSigner;
import tech.pegasys.web3signer.signing.ValidatorManager;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class EnclaveKeysReadOnlyTest {
  private final BLSKeyPair key = EnclaveTestKeys.randomKeys(1).get(0);
  private final ArtifactSignerProvider provider = mock(ArtifactSignerProvider.class);
  private InProcessEnclaveSigner enclave;
  private EnclaveClient client;
  private EnclaveBlsArtifactSigner signer;

  @BeforeEach
  void setUp() {
    enclave = new InProcessEnclaveSigner();
    EnclaveTestKeys.provision(enclave.address(), List.of(key));
    client = EnclaveClient.create(enclave.address(), new EnclaveClient.Options(1, 5000));
    signer = new EnclaveBlsArtifactSigner(client, key.getPublicKey().toBytesCompressed().toArray());
    when(provider.getSigner(signer.getIdentifier())).thenReturn(Optional.of(signer));
    when(provider.availableIdentifiers()).thenReturn(Set.of(signer.getIdentifier()));
  }

  @AfterEach
  void tearDown() {
    client.close();
    enclave.close();
  }

  @Test
  void deletingAnEnclaveKeyIsRefusedAndTheKeyStaysSignable() {
    final ValidatorManager validatorManager = mock(ValidatorManager.class);
    final DeleteKeystoresProcessor processor =
        new DeleteKeystoresProcessor(Optional.empty(), provider, validatorManager);

    final DeleteKeystoresResponse response =
        processor.process(new DeleteKeystoresRequestBody(List.of(signer.getIdentifier())));

    assertThat(response.getData()).hasSize(1);
    assertThat(response.getData().get(0).getStatus()).isEqualTo(DeleteKeystoreStatus.ERROR);
    assertThat(response.getData().get(0).getMessage())
        .isEqualTo("Unable to delete readonly key: " + signer.getIdentifier());
    verify(validatorManager, never()).deleteValidator(any());

    final Bytes root = Bytes.random(32);
    final BlsArtifactSignature signature = signer.sign(root);
    assertThat(signature.getSignatureData()).isEqualTo(BLS.sign(key.getSecretKey(), root));
  }

  @Test
  void listShowsEnclaveKeysAsReadOnly() throws Exception {
    final RoutingContext context = mock(RoutingContext.class);
    final HttpServerResponse response = mock(HttpServerResponse.class);
    when(context.response()).thenReturn(response);
    when(response.putHeader(any(CharSequence.class), any(CharSequence.class))).thenReturn(response);
    when(response.setStatusCode(anyInt())).thenReturn(response);

    new ListKeystoresHandler(provider, new ObjectMapper()).handle(context);

    final ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
    verify(response).end(body.capture());
    assertThat(new ObjectMapper().readTree(body.getValue()).get("data"))
        .singleElement()
        .satisfies(
            entry -> {
              assertThat(entry.get("validating_pubkey").asText()).isEqualTo(signer.getIdentifier());
              assertThat(entry.get("derivation_path").isNull()).isTrue();
              assertThat(entry.get("readonly").asBoolean()).isTrue();
            });
  }
}
