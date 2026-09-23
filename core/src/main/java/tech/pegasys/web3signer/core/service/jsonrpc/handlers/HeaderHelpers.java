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
package tech.pegasys.web3signer.core.service.jsonrpc.handlers;

import java.util.List;

import com.google.common.net.HttpHeaders;
import io.vertx.core.MultiMap;

public class HeaderHelpers {

  public static MultiMap createHeaders(final MultiMap headers) {
    final MultiMap headersToReturn = MultiMap.caseInsensitiveMultiMap();
    headers.forEach(entry -> headersToReturn.add(entry.getKey(), entry.getValue()));

    headersToReturn.remove(HttpHeaders.CONTENT_LENGTH);
    headersToReturn.remove(HttpHeaders.ORIGIN);
    renameHeader(headersToReturn, HttpHeaders.HOST, HttpHeaders.X_FORWARDED_HOST);

    return headersToReturn;
  }

  private static void renameHeader(
      final MultiMap headers, final String oldHeader, final String newHeader) {
    final List<String> oldHeaderValue = headers.getAll(oldHeader);
    headers.remove(oldHeader);
    if (oldHeaderValue != null) {
      headers.add(newHeader, oldHeaderValue);
    }
  }
}
