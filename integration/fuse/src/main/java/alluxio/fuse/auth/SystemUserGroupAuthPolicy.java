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

package alluxio.fuse.auth;

import alluxio.AlluxioURI;
import alluxio.client.file.FileSystem;
import alluxio.client.file.URIStatus;
import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.fuse.AlluxioFuseUtils;
import alluxio.grpc.SetAttributePOptions;
import alluxio.jnifuse.AbstractFuseFileSystem;
import alluxio.jnifuse.struct.FuseContext;
import alluxio.security.CurrentUser;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

/**
 * Default Fuse Auth Policy.
 */
public final class SystemUserGroupAuthPolicy implements AuthPolicy {
  private static final Logger LOG = LoggerFactory.getLogger(
      SystemUserGroupAuthPolicy.class);

  private final FileSystem mFileSystem;
  private final AbstractFuseFileSystem mFuseFileSystem;
  private final boolean mIsUserGroupTranslation;
  private final LoadingCache<Long, String> mUsernameCache;
  private final LoadingCache<Long, String> mGroupnameCache;

  /**
   * @param fileSystem     the Alluxio file system
   * @param conf           alluxio configuration
   * @param fuseFileSystem AbstractFuseFileSystem
   */
  public SystemUserGroupAuthPolicy(
      FileSystem fileSystem, AlluxioConfiguration conf, AbstractFuseFileSystem fuseFileSystem) {
    mFileSystem = fileSystem;
    mFuseFileSystem = fuseFileSystem;

    mUsernameCache = CacheBuilder.newBuilder()
        .maximumSize(100)
        .build(new CacheLoader<Long, String>() {
          @Override
          public String load(Long uid) {
            return AlluxioFuseUtils.getUserName(uid);
          }
        });
    mGroupnameCache = CacheBuilder.newBuilder()
        .maximumSize(100)
        .build(new CacheLoader<Long, String>() {
          @Override
          public String load(Long gid) {
            return AlluxioFuseUtils.getGroupName(gid);
          }
        });
    mIsUserGroupTranslation = conf.getBoolean(PropertyKey.FUSE_USER_GROUP_TRANSLATION_ENABLED);
  }

  public FileSystem getFileSystemByUser(AlluxioConfiguration conf) throws Exception {
    FuseContext fc = mFuseFileSystem.getContext();
    if (!mIsUserGroupTranslation) {
      return mFileSystem;
    }
    final Subject subject = new Subject();
    long uid = fc.uid.get();
    String currentUser = mUsernameCache.get(uid);
    if (StringUtils.isNotEmpty(currentUser)) {
      subject.getPrincipals().add(new CurrentUser(currentUser));
    }
    return FileSystem.Factory.get(subject, conf);
  }

  @Override
  public void setUserGroupIfNeeded(FileSystem fileSystem, AlluxioURI uri) throws Exception {
    FuseContext fc = mFuseFileSystem.getContext();
    if (!mIsUserGroupTranslation) {
      return;
    }
    long uid = fc.uid.get();
    long gid = fc.gid.get();
    if (uid == AlluxioFuseUtils.ID_NOT_SET_VALUE
        || uid == AlluxioFuseUtils.ID_NOT_SET_VALUE_UNSIGNED
        || gid == AlluxioFuseUtils.ID_NOT_SET_VALUE
        || gid == AlluxioFuseUtils.ID_NOT_SET_VALUE_UNSIGNED) {
      // cannot get valid uid or gid
      return;
    }
    if (uid == AlluxioFuseUtils.DEFAULT_UID && gid == AlluxioFuseUtils.DEFAULT_GID) {
      // no need to set attribute
      return;
    }
    String groupName = gid != AlluxioFuseUtils.DEFAULT_GID
        ? mGroupnameCache.get(gid) : AlluxioFuseUtils.DEFAULT_GROUP_NAME;
    String userName = uid != AlluxioFuseUtils.DEFAULT_UID
        ? mUsernameCache.get(uid) : AlluxioFuseUtils.DEFAULT_USER_NAME;
    if (userName.isEmpty() || groupName.isEmpty()) {
      // cannot get valid user name and group name
      return;
    }

    URIStatus status = fileSystem.getStatus(uri);
    if (userName.equals(status.getOwner()) && groupName.equals(status.getGroup())) {
      return;
    }

    SetAttributePOptions attributeOptions = SetAttributePOptions.newBuilder()
        .setGroup(groupName)
        .setOwner(userName)
        .build();
    LOG.debug("Set attributes of path {} to {}", uri, attributeOptions);
    fileSystem.setAttribute(uri, attributeOptions);
  }
}
