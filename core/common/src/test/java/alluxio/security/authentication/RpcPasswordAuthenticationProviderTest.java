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

package alluxio.security.authentication;

import static org.junit.Assert.assertTrue;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.InstancedConfiguration;
import alluxio.security.authentication.password.RpcPasswordAuthenticationProvider;
import alluxio.security.authentication.plain.CustomAuthenticationProvider;
import alluxio.util.ConfigurationUtils;

import org.junit.Test;

public class RpcPasswordAuthenticationProviderTest {
  private static AlluxioConfiguration sConf =
            new InstancedConfiguration(ConfigurationUtils.defaults());

  /**
   * Tests the {@link CustomAuthenticationProvider#getCustomProvider()} method.
   */
  @Test
  public void mockRpcPasswordProvider() {
    RpcPasswordAuthenticationProvider provider = new RpcPasswordAuthenticationProvider(sConf);
    assertTrue(provider instanceof AuthenticationProvider);
  }
}
