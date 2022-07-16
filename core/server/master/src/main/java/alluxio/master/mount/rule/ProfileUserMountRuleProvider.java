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
import alluxio.util.Time;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class ProfileUserMountRuleProvider implements UserMountRuleProvider {

  private static final Logger LOG = LoggerFactory.getLogger(ProfileUserMountRuleProvider.class);

  private String mMappingFile;
  private long mCacheTimeout;
  private volatile AtomicLong mLastRefreshTime = new AtomicLong(-1L);
  private AtomicReference<ConcurrentHashMap<String, String>>
          mCacheRef = new AtomicReference<>();

  @Override
  public void init(AlluxioConfiguration conf) {
    mMappingFile = conf.get(PropertyKey.SECURITY_USER_MOUNT_MAPPING_FILE);
    mCacheTimeout = conf.getLong(PropertyKey.SECURITY_USER_MOUNT_MAPPING_FILE_CACHE_SEC) * 1000;
  }

  private boolean isTimeout() {
    return Time.now() - mLastRefreshTime.get() > mCacheTimeout;
  }

  private void cacheFailure(String reason) throws IOException {
    throw new IOException(reason);
  }

  public void cacheRefresh(boolean force) throws IOException {
    long start = Time.now();
    if (!force) {
      // If not force refresh, check the timeout again
      if (!isTimeout()) {
        return;
      }
    }
    BufferedReader br = null;
    ConcurrentHashMap<String, String> updateCache = new ConcurrentHashMap<>();

    try {
      FileInputStream file = new FileInputStream(mMappingFile);
      Reader fr = new InputStreamReader(file, StandardCharsets.UTF_8);
      br = new BufferedReader(fr);
      String line;
      while ((line = br.readLine()) != null) {
        //process the line
        try {
          processRow(updateCache, line);
        } catch (IllegalRuleLineException e) {
          LOG.error("Unable to process rule line: " + line, start);
        }
      }
    } catch (IOException e) {
      throw e;
    } finally {
      if (br != null) {
        br.close();
      }
    }

    if (updateCache.isEmpty()) {
      mLastRefreshTime.set(Time.now());
      cacheFailure("New rule file is empty");
    }
    mCacheRef.set(updateCache);
    mLastRefreshTime.set(Time.now());
    LOG.info("Refreshed " + updateCache.size() + " records from rule file.");
  }

  public String getMountRule(String user) {
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
      return null;
    }
    return mCacheRef.get().get(user);
  }

  private void processRow(ConcurrentHashMap<String, String> cache,
      String string) throws IllegalRuleLineException {
    // handle comment line
    if (string.startsWith("#")) {
      return;
    }
    if (string.split("=").length != 2) {
      throw new IllegalRuleLineException(string);
    }
    String user = string.split("=")[0];
    String path = string.split("=")[1];
    cache.put(user, path);
  }

  private static class IllegalRuleLineException extends IOException {

    public IllegalRuleLineException(String message) {
      super(message);
    }

    @Override
    public String toString() {
      final StringBuilder sb =
              new StringBuilder("IllegalRuleLineException ");
      sb.append(super.getMessage());
      return sb.toString();
    }
  }
}
