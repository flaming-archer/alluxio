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

package alluxio.master.file;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.Configuration;
import alluxio.conf.PropertyKey;
import alluxio.exception.AccessControlException;
import alluxio.exception.ExceptionMessage;
import alluxio.exception.InvalidPathException;
import alluxio.master.file.meta.InodeTree;
import alluxio.master.file.meta.LockedInodePath;
import alluxio.security.authentication.AuthenticatedClientUser;
import alluxio.security.authorization.Mode;
import alluxio.util.CommonUtils;
import alluxio.util.io.PathUtils;

import com.google.common.base.Preconditions;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Permission checker backed by Apache Ranger policy decisions.
 */
public class RangerPermissionChecker implements PermissionChecker {
  private final DefaultPermissionChecker mDelegate;
  private final boolean mRangerEnabled;
  private final RangerAuthorizer mAuthorizer;

  /**
   * @param inodeTree inode tree
   */
  public RangerPermissionChecker(InodeTree inodeTree) {
    this(inodeTree, Configuration.global());
  }

  /**
   * @param inodeTree inode tree
   * @param conf config
   */
  public RangerPermissionChecker(InodeTree inodeTree, AlluxioConfiguration conf) {
    mDelegate = new DefaultPermissionChecker(Preconditions.checkNotNull(inodeTree, "inodeTree"));
    mRangerEnabled = conf.getBoolean(PropertyKey.SECURITY_AUTHORIZATION_PERMISSION_RANGER_ENABLED);
    if (mRangerEnabled) {
      mAuthorizer = CommonUtils.createNewClassInstance(conf.<RangerAuthorizer>getClass(
              PropertyKey.SECURITY_AUTHORIZATION_PERMISSION_RANGER_AUTHORIZER_CLASS),
          null, null);
      mAuthorizer.init(conf);
    } else {
      mAuthorizer = null;
    }
  }

  @Override
  public void checkParentPermission(Mode.Bits bits, LockedInodePath inodePath)
      throws AccessControlException, InvalidPathException {
    mDelegate.checkParentPermission(bits, inodePath);
    if (!mRangerEnabled || PathUtils.isRoot(inodePath.getUri().getPath())) {
      return;
    }
    String parent = PathUtils.getParent(inodePath.getUri().getPath());
    checkRangerAccess(bits, parent);
  }

  @Override
  public void checkPermission(Mode.Bits bits, LockedInodePath inodePath)
      throws AccessControlException {
    mDelegate.checkPermission(bits, inodePath);
    if (!mRangerEnabled) {
      return;
    }
    checkRangerAccess(bits, inodePath.getUri().getPath());
  }

  @Override
  public void checkSuperUser() throws AccessControlException {
    mDelegate.checkSuperUser();
  }

  @Override
  public Mode.Bits getPermission(LockedInodePath inodePath) {
    Mode.Bits mode = mDelegate.getPermission(inodePath);
    if (!mRangerEnabled || mode == Mode.Bits.NONE) {
      return mode;
    }
    try {
      Mode.Bits result = Mode.Bits.NONE;
      if (hasRangerAccess(Mode.Bits.READ, inodePath.getUri().getPath())) {
        result = result.or(Mode.Bits.READ);
      }
      if (hasRangerAccess(Mode.Bits.WRITE, inodePath.getUri().getPath())) {
        result = result.or(Mode.Bits.WRITE);
      }
      if (hasRangerAccess(Mode.Bits.EXECUTE, inodePath.getUri().getPath())) {
        result = result.or(Mode.Bits.EXECUTE);
      }
      return result;
    } catch (AccessControlException e) {
      return Mode.Bits.NONE;
    }
  }

  @Override
  public void checkSetAttributePermission(LockedInodePath inodePath, boolean superuserRequired,
      boolean ownerRequired, boolean writeRequired)
      throws AccessControlException, InvalidPathException {
    mDelegate.checkSetAttributePermission(
        inodePath, superuserRequired, ownerRequired, writeRequired);
    if (mRangerEnabled && writeRequired) {
      checkRangerAccess(Mode.Bits.WRITE, inodePath.getUri().getPath());
    }
  }

  private void checkRangerAccess(Mode.Bits bits, String path) throws AccessControlException {
    if (!hasRangerAccess(bits, path)) {
      String user = AuthenticatedClientUser.getClientUser(Configuration.global());
      throw new AccessControlException(ExceptionMessage.PERMISSION_DENIED
          .getMessage(String.format(
              "user=%s, path=%s, access=%s denied by Ranger", user, path, bits)));
    }
  }

  private boolean hasRangerAccess(Mode.Bits bits, String path) throws AccessControlException {
    try {
      String user = AuthenticatedClientUser.getClientUser(Configuration.global());
      List<String> groups = CommonUtils.getGroups(user, Configuration.global());
      if (bits == Mode.Bits.ALL) {
        return hasRangerAccess(Mode.Bits.READ, path)
            && hasRangerAccess(Mode.Bits.WRITE, path)
            && hasRangerAccess(Mode.Bits.EXECUTE, path);
      }
      return mAuthorizer.isAccessAllowed(user, groups, path, toAccessType(bits));
    } catch (IOException e) {
      throw new AccessControlException(
          ExceptionMessage.PERMISSION_DENIED.getMessage(e.getMessage()));
    }
  }

  private String toAccessType(Mode.Bits bits) {
    switch (bits) {
      case READ:
        return "read";
      case WRITE:
        return "write";
      case EXECUTE:
        return "execute";
      default:
        return bits.toString().toLowerCase();
    }
  }

  /** Ranger authorization adapter. */
  public interface RangerAuthorizer {
    /**
     * Initializes the authorizer.
     *
     * @param conf config
     */
    default void init(AlluxioConfiguration conf) {
      // no-op
    }

    /**
     * @param user user
     * @param groups groups
     * @param path path
     * @param accessType access type string
     * @return whether access is allowed
     */
    boolean isAccessAllowed(String user, List<String> groups, String path, String accessType);
  }

  /**
   * Ranger authorizer implementation backed by RangerBasePlugin via reflection.
   */
  public static class RangerPluginAuthorizer implements RangerAuthorizer {
    private Object mPlugin;
    private Class<?> mRequestInterface;
    private String mResourceKey;

    @Override
    public void init(AlluxioConfiguration conf) {
      try {
        String serviceType = conf.getString(
            PropertyKey.SECURITY_AUTHORIZATION_PERMISSION_RANGER_SERVICE_TYPE);
        String appId = conf.getString(
            PropertyKey.SECURITY_AUTHORIZATION_PERMISSION_RANGER_APP_ID);
        Class<?> pluginClass =
            Class.forName("org.apache.ranger.plugin.service.RangerBasePlugin");
        mResourceKey = conf.getString(
            PropertyKey.SECURITY_AUTHORIZATION_PERMISSION_RANGER_RESOURCE_KEY);
        mPlugin = pluginClass.getConstructor(String.class, String.class)
            .newInstance(serviceType, appId);
        pluginClass.getMethod("init").invoke(mPlugin);
        mRequestInterface =
            Class.forName("org.apache.ranger.plugin.policyengine.RangerAccessRequest");
      } catch (Exception e) {
        throw new IllegalStateException("Failed to initialize Ranger plugin authorizer", e);
      }
    }

    @Override
    public boolean isAccessAllowed(String user, List<String> groups, String path,
        String accessType) {
      try {
        Class<?> resourceClass =
            Class.forName("org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl");
        Object resource = resourceClass.getConstructor().newInstance();
        resourceClass.getMethod("setValue", String.class, String.class)
            .invoke(resource, mResourceKey, path);

        Class<?> requestClass =
            Class.forName("org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl");
        Object request = requestClass.getConstructor().newInstance();
        requestClass.getMethod("setResource", Class.forName(
            "org.apache.ranger.plugin.policyengine.RangerAccessResource"))
            .invoke(request, resource);
        requestClass.getMethod("setUser", String.class).invoke(request, user);
        Method setGroups = requestClass.getMethod("setUserGroups", Set.class);
        setGroups.invoke(request, groups == null ? Collections.emptySet() : new HashSet<>(groups));
        requestClass.getMethod("setAccessType", String.class).invoke(request, accessType);

        Object result = mPlugin.getClass().getMethod("isAccessAllowed", mRequestInterface)
            .invoke(mPlugin, request);
        return (boolean) result.getClass().getMethod("getIsAllowed").invoke(result);
      } catch (Exception e) {
        throw new IllegalStateException("Ranger access check failed", e);
      }
    }
  }
}
