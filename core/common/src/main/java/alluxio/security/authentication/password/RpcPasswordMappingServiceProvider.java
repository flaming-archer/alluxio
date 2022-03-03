/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.security.authentication.password;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.util.CommonUtils;
import alluxio.util.network.tls.SslContextProvider;

import java.io.IOException;

public interface RpcPasswordMappingServiceProvider {

  /**
   * Factory for creating context provider implementations.
   */
  class Factory {
    private Factory() {} // prevent instantiation

    /**
     * Creates and initializes {@link SslContextProvider} implementation
     * based on Alluxio configuration.
     *
     * @return the generated {@link SslContextProvider} instance
     */
    public static RpcPasswordMappingServiceProvider create(AlluxioConfiguration conf) {
      RpcPasswordMappingServiceProvider provider = CommonUtils.createNewClassInstance(
              conf.getClass(PropertyKey.SECURITY_RPC_PASSWORD_MAPPING), null, null);
      provider.init(conf);
      return provider;
    }
  }

  /**
   * Initializes provider.
   *
   * @param conf Alluxio configuration
   */
  void init(AlluxioConfiguration conf);

  /**
   * Get rpc password of a given user.
   * Returns null in case of non-existing user
   * @param user User's name
   * @return password of user
   * @throws IOException
   */
  public String getRpcPassword(String user) throws IOException;

  /**
   * Check if it is a bypass user.
   * @param user User's name
   * @return bypass user or not
   * @throws IOException
   */
  public boolean isBypassUser(String user) throws IOException;

  /**
   * Refresh the cache.
   * @param force force refresh
   * @throws IOException
   */
  public void cacheRefresh(boolean force) throws IOException;
}
