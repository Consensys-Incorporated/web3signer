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
package db;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

/**
 * Gives each test a new migrated database, injectable as a {@link Jdbi} or an open {@link Handle};
 * JUnit closes the handle with the test's store.
 */
public class DatabaseSetupExtension implements BeforeEachCallback, ParameterResolver {

  private static final Namespace NAMESPACE = Namespace.create(DatabaseSetupExtension.class);

  @Override
  public void beforeEach(final ExtensionContext context) {
    final Jdbi jdbi = DatabaseUtil.create().jdbi();
    context.getStore(NAMESPACE).put(Jdbi.class, jdbi);
    context.getStore(NAMESPACE).put(Handle.class, jdbi.open());
  }

  @Override
  public boolean supportsParameter(
      final ParameterContext parameterContext, final ExtensionContext extensionContext) {
    final Class<?> type = parameterContext.getParameter().getType();
    return type.equals(Handle.class) || type.equals(Jdbi.class);
  }

  @Override
  public Object resolveParameter(
      final ParameterContext parameterContext, final ExtensionContext extensionContext) {
    return extensionContext.getStore(NAMESPACE).get(parameterContext.getParameter().getType());
  }
}
