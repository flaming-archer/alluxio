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
import alluxio.util.MD5FileUtils;
import alluxio.util.MD5Utils.MD5Hash;
import alluxio.util.Time;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class ShadowFileRpcPasswordMapping implements RpcPasswordMappingServiceProvider {
  private static final Logger LOG = LoggerFactory.getLogger(ShadowFileRpcPasswordMapping.class);

  private String mShadowFile;

  private long mCacheTimeout;

  private volatile AtomicLong mLastRefreshTime = new AtomicLong(-1L);

  private boolean mChecksumEnabled;

  private volatile boolean mStartup = true;

  private AtomicReference<ConcurrentHashMap<String, RpcPassword>>
          mCacheRef = new AtomicReference<>();

  private IOException IllegalShadowLineException(String line) {
    return new IOException("Illegal shadow line: " + line);
  }

  @Override
  public void init(AlluxioConfiguration conf) {
    mShadowFile = conf.get(PropertyKey.SECURITY_RPC_PASSWORD_SHADOW_FILE);
    mCacheTimeout = conf.getLong(PropertyKey.SECURITY_RPC_PASSWORD_SHADOW_FILE_CACHE_SEC) * 1000;
    mChecksumEnabled = conf.getBoolean(
            PropertyKey.SECURITY_RPC_PASSWORD_SHADOW_FILE_CHECKSUM_ENABLED);
  }

  @Override
  public boolean isBypassUser(String user) throws IOException {
    try {
      if (mCacheRef.get() == null || mCacheRef.get().size() == 0) {
        cacheRefresh(true);
      }
      if (isTimeout()) {
        cacheRefresh(false);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    if (!mCacheRef.get().containsKey(user)) {
      return false;
    }
    return mCacheRef.get().get(user).isBypass();
  }

  @Override
  public void cacheRefresh(boolean force) throws IOException {
    long start = Time.now();
    if (!force) {
      // If not force refresh, check the timeout again
      if (!isTimeout()) {
        return;
      }
    }
    BufferedReader br = null;
    ConcurrentHashMap<String, RpcPassword> updateCache =
            new ConcurrentHashMap<>();

    MD5Hash md5Hash = null;
    if (mChecksumEnabled && !mStartup) {
      md5Hash = checksum();
      if (md5Hash == null) {
        refreshFailure("First round checksum not match.", start);
      }
    }

    try {
      FileInputStream file = new FileInputStream(mShadowFile);
      Reader fr = new InputStreamReader(file, StandardCharsets.UTF_8);
      br = new BufferedReader(fr);
      String line;
      while ((line = br.readLine()) != null) {
        //process the line
        try {
          processRow(updateCache, line);
        } catch (IllegalShadowLineException e) {
          LOG.error("Unable to process shadow line: " + line, start);
        }
      }
    } catch (IOException e) {
      throw e;
    } finally {
      if (br != null) {
        br.close();
      }
    }

    if (mChecksumEnabled && !mStartup) {
      MD5Hash fileHash = MD5FileUtils.computeMd5ForFile(new File(mShadowFile));
      if (md5Hash != null && !md5Hash.equals(fileHash)) {
        refreshFailure("Second round checksum not match", start);
      }
    }
    if (updateCache.isEmpty()) {
      refreshFailure("New shadowFile is empty", start);
    }
    mCacheRef.set(updateCache);
    mLastRefreshTime.set(Time.now());
    LOG.info("Refreshed " + updateCache.size() + " records from shadowFile.");
    if (mStartup) {
      mStartup = false;
    }
  }

  private MD5Hash checksum() {
    MD5Hash result = null;
    try {
      MD5Hash fileHash = MD5FileUtils.computeMd5ForFile(new File(mShadowFile));
      MD5Hash storedHash = MD5FileUtils.readStoredMd5ForFile(new File(mShadowFile));
      if (storedHash == null) {
        LOG.error("MD5 File not exists: "
                + MD5FileUtils.getDigestFileForFile(new File(mShadowFile)));
      }
      if (!fileHash.equals(storedHash)) {
        return null;
      }
      result = fileHash;
    } catch (IOException e) {
      LOG.error("Error checksum: " + e.getMessage());
    }
    return result;
  }

  /**
   * Returns rpcPassword for a user.
   * @param userName get rpcPassword for this user
   * @return list of rpcPassword for a given user
   */
  @Override
  public String getRpcPassword(String userName) {
    try {
      if (mCacheRef.get() == null || mCacheRef.get().size() == 0) {
        cacheRefresh(true);
      }
      if (isTimeout()) {
        cacheRefresh(false);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    if (!mCacheRef.get().containsKey(userName)) {
      return null;
    }
    return mCacheRef.get().get(userName).getRpcPassword();
  }

  private void processRow(ConcurrentHashMap<String, RpcPassword> cache,
                          String string) throws IllegalShadowLineException {
    // handle comment line
    if (string.startsWith("#")) {
      return;
    }
    if (string.split(",").length != 3) {
      throw new IllegalShadowLineException(string);
    }
    String user = string.split(",")[0];
    String shadow = string.split(",")[1];
    boolean bypass = string.split(",")[2].equalsIgnoreCase("true");
    cache.put(user, new RpcPassword(shadow, bypass));
  }

  private boolean isTimeout() {
    return Time.now() - mLastRefreshTime.get() > mCacheTimeout;
  }

  private void refreshFailure(String reason, long start)
          throws IOException {
    mLastRefreshTime.set(Time.now());
    throw new IOException(reason);
  }

  private static class IllegalShadowLineException extends IOException {
    public IllegalShadowLineException(String message) {
      super(message);
    }

    public IllegalShadowLineException(String message, Throwable err) {
      super(message, err);
    }

    @Override
    public String toString() {
      final StringBuilder sb =
              new StringBuilder("IllegalShadowLineException ");
      sb.append(super.getMessage());
      return sb.toString();
    }
  }
}
