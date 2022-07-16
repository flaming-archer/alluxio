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

package alluxio.master.mount.rule;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.util.CommonUtils;

import java.io.IOException;

public interface UserMountRuleProvider {

  void init(AlluxioConfiguration conf);

  /**
   * Factory for {@link UserMountRuleProvider}.
   */
  class Factory {
    // prevent instantiation
    private Factory() {}

    /**
     * Creates and initializes {@link UserMountRuleProvider} implementation
     * based on Alluxio configuration.
     *
     * @return the generated {@link UserMountRuleProvider}
     */
    public static UserMountRuleProvider create(AlluxioConfiguration conf) {
      UserMountRuleProvider provider = CommonUtils.createNewClassInstance(
          conf.getClass(PropertyKey.SECURITY_USER_MOUNT_MAPPING_CLASSNAME), null, null);
      provider.init(conf);
      return provider;
    }
  }

  /**
   * Get the parent paths of the mount point that the user is allowed to mount.
   *
   * @param user The username performing mount operation
   * @return The mount point parent paths, return null if there is no rule
   * @throws IOException when failed to get mount rule
   */
  public String getMountRule(String user) throws IOException;
}
