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
package tech.pegasys.web3signer.signing;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static tech.pegasys.web3signer.bls.keystore.model.Pbkdf2PseudoRandomFunction.HMAC_SHA256;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.BLSTestUtil;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.model.CipherFunction;
import tech.pegasys.web3signer.bls.keystore.model.CipherParam;
import tech.pegasys.web3signer.bls.keystore.model.CipherSpec;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.web3signer.signing.config.metadata.SignerOrigin;
import tech.pegasys.web3signer.signing.config.metadata.parser.SigningMetadataModule;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DefaultValidatorManagerTest {
  private static final Bytes SALT =
      Bytes.fromHexString("0x9ac471d9d421bc06d9aefe2b46cf96d11829c51e36ed0b116132be57a9f8c22b");
  private static final CipherParam IV =
      new CipherParam(Bytes.fromHexString("0xcca2c67ec95a1dd13edd986fea372789"));
  private static final BLSKeyPair BLS_KEY_PAIR = BLSTestUtil.randomKeyPair(1);
  private static final ObjectMapper OBJECT_MAPPER =
      JsonMapper.builder().addModule(new SigningMetadataModule()).build();

  @Mock private ArtifactSignerProvider artifactSignerProvider;
  @Mock private KeystoreFileManager keystoreFileManager;

  @Test
  @SuppressWarnings("unchecked")
  void addsValidator()
      throws IOException, ExecutionException, InterruptedException, JsonProcessingException {
    final Future<Void> futureAddSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.addSigner(any(), any())).thenReturn(futureAddSigner);

    final String keystoreJson = createKeystoreString();
    final BlsArtifactSigner signer =
        new BlsArtifactSigner(BLS_KEY_PAIR, SignerOrigin.FILE_KEYSTORE);
    final KeystoreFileRecord fileRecord =
        new KeystoreFileRecord(keystoreJson, "password", BLS_KEY_PAIR.getPublicKey().toString());
    final Path keyConfigFile = Path.of("/keys", fileRecord.metadataFileName());
    when(keystoreFileManager.createKeystoreFiles(fileRecord)).thenReturn(keyConfigFile);

    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.of(keystoreFileManager));
    defaultValidatorManager.addValidator(signer, fileRecord);

    // the provider learns the written key config file, so a reload can attribute the key to it
    verify(artifactSignerProvider).addSigner(eq(signer), eq(Optional.of(keyConfigFile)));
    verify(futureAddSigner).get();
  }

  @Test
  @SuppressWarnings("unchecked")
  void deletesValidator() throws ExecutionException, InterruptedException, IOException {
    final Future<Void> futureDeleteSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.removeSigner(any())).thenReturn(futureDeleteSigner);
    when(keystoreFileManager.deleteKeystoreFiles(any())).thenReturn(true);

    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.of(keystoreFileManager));
    defaultValidatorManager.deleteValidator(BLS_KEY_PAIR.getPublicKey().toBytesCompressed());

    verify(artifactSignerProvider).removeSigner(eq(BLS_KEY_PAIR.getPublicKey().toString()));
    verify(keystoreFileManager).deleteKeystoreFiles(eq(BLS_KEY_PAIR.getPublicKey().toString()));
    verify(futureDeleteSigner).get();
  }

  @Test
  @SuppressWarnings("unchecked")
  void deleteValidatorThrowsWhenFilesNotDeleted()
      throws ExecutionException, InterruptedException, IOException {
    final Future<Void> futureDeleteSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.removeSigner(any())).thenReturn(futureDeleteSigner);
    when(keystoreFileManager.deleteKeystoreFiles(any())).thenReturn(false);

    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.of(keystoreFileManager));

    assertThatThrownBy(
            () ->
                defaultValidatorManager.deleteValidator(
                    BLS_KEY_PAIR.getPublicKey().toBytesCompressed()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Unable to delete keystore files");
    verify(artifactSignerProvider).removeSigner(eq(BLS_KEY_PAIR.getPublicKey().toString()));
  }

  @Test
  @SuppressWarnings("unchecked")
  void addsValidatorWithoutFileStorage()
      throws ExecutionException, InterruptedException, IOException {
    final Future<Void> futureAddSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.addSigner(any(), any())).thenReturn(futureAddSigner);

    final BlsArtifactSigner signer =
        new BlsArtifactSigner(BLS_KEY_PAIR, SignerOrigin.FILE_KEYSTORE);

    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.empty());
    defaultValidatorManager.addValidator(signer, null);

    verify(artifactSignerProvider)
        .addSigner(
            argThat(
                s ->
                    s instanceof BlsArtifactSigner blsSigner
                        && s.getIdentifier().equals(BLS_KEY_PAIR.getPublicKey().toString())
                        && !blsSigner.isReadOnlyKey()),
            eq(Optional.empty()));
    verify(keystoreFileManager, never()).createKeystoreFiles(any());
    verify(futureAddSigner).get();
  }

  @Test
  @SuppressWarnings("unchecked")
  void deletesValidatorWithoutFileStorage()
      throws ExecutionException, InterruptedException, IOException {
    final Future<Void> futureDeleteSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.removeSigner(any())).thenReturn(futureDeleteSigner);

    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.empty());
    defaultValidatorManager.deleteValidator(BLS_KEY_PAIR.getPublicKey().toBytesCompressed());

    verify(artifactSignerProvider).removeSigner(eq(BLS_KEY_PAIR.getPublicKey().toString()));
    verify(keystoreFileManager, never()).deleteKeystoreFiles(any());
    verify(futureDeleteSigner).get();
  }

  @Test
  @SuppressWarnings("unchecked")
  void addValidatorThrowsExceptionWhenFutureGetFails()
      throws ExecutionException, InterruptedException {
    final Future<Void> futureAddSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.addSigner(any(), any())).thenReturn(futureAddSigner);
    when(futureAddSigner.get())
        .thenThrow(new ExecutionException(new RuntimeException("Test exception")));

    final BlsArtifactSigner signer =
        new BlsArtifactSigner(BLS_KEY_PAIR, SignerOrigin.FILE_KEYSTORE);
    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.empty());

    assertThatThrownBy(() -> defaultValidatorManager.addValidator(signer, null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Unable to add validator");
  }

  @Test
  @SuppressWarnings("unchecked")
  void deleteValidatorThrowsExceptionWhenFutureGetFails()
      throws ExecutionException, InterruptedException {
    final Future<Void> futureDeleteSigner = Mockito.mock(Future.class);
    when(artifactSignerProvider.removeSigner(any())).thenReturn(futureDeleteSigner);
    when(futureDeleteSigner.get()).thenThrow(new InterruptedException("Test exception"));

    final DefaultValidatorManager defaultValidatorManager =
        new DefaultValidatorManager(artifactSignerProvider, Optional.empty());

    assertThatThrownBy(
            () ->
                defaultValidatorManager.deleteValidator(
                    BLS_KEY_PAIR.getPublicKey().toBytesCompressed()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Unable to delete validator");
  }

  private String createKeystoreString() throws JsonProcessingException {
    final CipherSpec cipher = new CipherSpec(CipherFunction.AES_128_CTR, IV);
    final Pbkdf2Param pbkdf2Param = new Pbkdf2Param(32, 262144, HMAC_SHA256, SALT);
    final KeyStoreData keyStoreData =
        KeyStore.encrypt(BLS_KEY_PAIR, "password", "", pbkdf2Param, cipher);

    return OBJECT_MAPPER.writeValueAsString(keyStoreData);
  }
}
