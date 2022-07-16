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
import alluxio.exception.AccessControlException;
import alluxio.exception.ExceptionMessage;
import alluxio.exception.InvalidPathException;
import alluxio.util.io.PathUtils;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class UserMountPointChecker {

  private static final Logger LOG =
          LoggerFactory.getLogger(UserMountPointChecker.class);

  private final UserMountRuleProvider mUserMountProvider;
  private final LoadingCache<String, String> mCache;
  private final long mCacheTimeout;

  public UserMountPointChecker(AlluxioConfiguration conf) {
    mUserMountProvider = UserMountRuleProvider.Factory.create(conf);
    mCacheTimeout = conf.getLong(PropertyKey.SECURITY_RPC_PASSWORD_CACHE_SECS) * 1000;
    mCache = CacheBuilder.newBuilder().refreshAfterWrite(mCacheTimeout, TimeUnit.MILLISECONDS)
            .expireAfterWrite(10 * mCacheTimeout, TimeUnit.MILLISECONDS)
            .build(new CacheLoader<String, String>() {
              @Override
              public String load(String user) throws Exception {
                return mUserMountProvider.getMountRule(user);
              }
            });
  }

  /**
   * Get the mount rule of a given user.
   *
   * @param user User's name
   * @return the mount points of the user can use
   * @throws IOException if user does not exist
   */
  public String getMountRule(final String user) throws IOException {
    try {
      return mCache.get(user);
    } catch (Exception e) {
      throw new IOException(e.getCause());
    }
  }

  /**
   * Check if the user is allowed to mount at the mount point.
   *
   * @param user The username performing mount operation
   * @param path The mount point
   *
   * @throws AccessControlException when the user is not allowed to mount to the Alluxio path
   */
  public void checkMountPoint(String user, String path) throws AccessControlException,
      InvalidPathException {
    try {
      String parentPathStr = getMountRule(user);
      if (parentPathStr != null) {
        String[] paths = parentPathStr.split(",");
        for (String parentPath : paths) {
          if (PathUtils.hasPrefix(path, parentPath)) {
            return;
          }
        }
      }
      throw new AccessControlException(ExceptionMessage.PERMISSION_DENIED
          .getMessage(String.format("user=%s is not allowed to mount ufs to the Alluxio path %s",
              user, path)));
    } catch (IOException e) {
      LOG.error("Mount point allowed for %s is not found", user, e);
      throw new AccessControlException(ExceptionMessage.PERMISSION_DENIED
          .getMessage(String.format("Mount point allowed for %s is not found", user)));
    }
  }
}
