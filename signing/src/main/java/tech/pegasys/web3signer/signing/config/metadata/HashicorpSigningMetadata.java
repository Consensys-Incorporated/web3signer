/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.signing.config.metadata;

import tech.pegasys.web3signer.keystorage.hashicorp.VaultAuthMethod;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.KeyType;

import java.net.http.HttpClient;
import java.nio.file.Path;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;

public class HashicorpSigningMetadata extends SigningMetadata {
  public static final String TYPE = "hashicorp";
  private final String serverHost;
  private final String keyPath;
  private String token;

  // Optional Fields (will be populated if need be).
  private Integer serverPort;
  private Long timeout;
  private String keyName;

  private Boolean tlsEnabled = false;
  private Path tlsKnownServerFile = null;
  private Path tlsTruststoreFile = null;
  private Path tlsTruststorePasswordFile = null;
  private HttpClient.Version httpProtocolVersion;

  private VaultAuthMethod authMethod = VaultAuthMethod.TOKEN;
  private String kubernetesRole;
  private Path kubernetesServiceAccountTokenPath;
  private String kubernetesAuthPath;

  @JsonCreator
  public HashicorpSigningMetadata(
      @JsonProperty(value = "serverHost", required = true) final String serverHost,
      @JsonProperty(value = "keyPath", required = true) final String keyPath,
      @JsonProperty(value = "keyType") final KeyType keyType) {
    super(TYPE, keyType != null ? keyType : KeyType.BLS);
    this.serverHost = serverHost;
    this.keyPath = keyPath;
  }

  @JsonSetter("token")
  public void setToken(final String value) {
    this.token = value;
  }

  @JsonSetter("serverPort")
  public void setServerPort(final Integer value) {
    this.serverPort = value;
  }

  @JsonSetter("timeout")
  public void setTimeout(final Long value) {
    this.timeout = value;
  }

  @JsonSetter("tlsEnabled")
  public void setTlsEnabled(final Boolean value) {
    this.tlsEnabled = value;
  }

  @JsonSetter("keyName")
  public void setKeyName(final String value) {
    this.keyName = value;
  }

  /**
   * Sets the known servers (fingerprint) file.
   *
   * @deprecated use {@link #setTlsTruststoreFile(Path)}
   */
  @Deprecated(forRemoval = true)
  @JsonSetter("tlsKnownServersPath")
  public void setTlsKnownServersPath(final Path value) {
    this.tlsKnownServerFile = value;
  }

  @JsonSetter("tlsTruststoreFile")
  public void setTlsTruststoreFile(final Path value) {
    this.tlsTruststoreFile = value;
  }

  @JsonSetter("tlsTruststorePasswordFile")
  public void setTlsTruststorePasswordFile(final Path value) {
    this.tlsTruststorePasswordFile = value;
  }

  @JsonSetter("httpProtocolVersion")
  public void setHttpProtocolVersion(final HttpClient.Version httpProtocolVersion) {
    this.httpProtocolVersion = httpProtocolVersion;
  }

  @JsonSetter("authMethod")
  public void setAuthMethod(final VaultAuthMethod authMethod) {
    if (authMethod != null) {
      this.authMethod = authMethod;
    }
  }

  @JsonSetter("kubernetesRole")
  public void setKubernetesRole(final String kubernetesRole) {
    this.kubernetesRole = kubernetesRole;
  }

  @JsonSetter("kubernetesServiceAccountTokenPath")
  public void setKubernetesServiceAccountTokenPath(final Path kubernetesServiceAccountTokenPath) {
    this.kubernetesServiceAccountTokenPath = kubernetesServiceAccountTokenPath;
  }

  @JsonSetter("kubernetesAuthPath")
  public void setKubernetesAuthPath(final String kubernetesAuthPath) {
    this.kubernetesAuthPath = kubernetesAuthPath;
  }

  public String getServerHost() {
    return serverHost;
  }

  public Integer getServerPort() {
    return serverPort;
  }

  public Long getTimeout() {
    return timeout;
  }

  public String getToken() {
    return token;
  }

  public String getKeyPath() {
    return keyPath;
  }

  public String getKeyName() {
    return keyName;
  }

  public Boolean getTlsEnabled() {
    return tlsEnabled;
  }

  /**
   * Returns the known servers (fingerprint) file.
   *
   * @deprecated use {@link #getTlsTruststoreFile()}
   */
  @Deprecated(forRemoval = true)
  public Path getTlsKnownServerFile() {
    return tlsKnownServerFile;
  }

  public Path getTlsTruststoreFile() {
    return tlsTruststoreFile;
  }

  public Path getTlsTruststorePasswordFile() {
    return tlsTruststorePasswordFile;
  }

  public HttpClient.Version getHttpProtocolVersion() {
    return httpProtocolVersion;
  }

  public VaultAuthMethod getAuthMethod() {
    return authMethod;
  }

  public String getKubernetesRole() {
    return kubernetesRole;
  }

  public Path getKubernetesServiceAccountTokenPath() {
    return kubernetesServiceAccountTokenPath;
  }

  public String getKubernetesAuthPath() {
    return kubernetesAuthPath;
  }

  @Override
  public ArtifactSigner createSigner(final ArtifactSignerFactory factory) {
    return factory.create(this);
  }
}
