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
import alluxio.conf.ServerConfiguration;

import java.util.concurrent.ConcurrentHashMap;

public class ConfigurationUserMountRuleProvider
    implements UserMountRuleProvider {

  ConcurrentHashMap<String, String> mUserMountRuleMap;

  @Override
  public void init(AlluxioConfiguration conf) {
    mUserMountRuleMap = new ConcurrentHashMap<>();
  }

  @Override
  public String getMountRule(String user) {
    if (mUserMountRuleMap.contains(user)) {
      return mUserMountRuleMap.get(user);
    } else {
      PropertyKey ownerMountConfKey = PropertyKey.Template.MASTER_MOUNT_PREFIX_PATH.format(user);
      String mountPointRule = ServerConfiguration.getOrDefault(ownerMountConfKey, null);
      mUserMountRuleMap.put(user, mountPointRule);
      return mountPointRule;
    }
  }
}
