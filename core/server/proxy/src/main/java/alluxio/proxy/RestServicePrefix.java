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

package alluxio.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public class RestServicePrefix {
  private static final Logger LOG = LoggerFactory.getLogger(RestServicePrefix.class);
  private List<ServicePrefix> mServicePrefixes;
  public static final String PROXY_S3_REST = "s3";
  public static final String ROOT_PREFIX = "/";
  private static final String PATH_PATTERN = "(\\/[a-zA-Z0-9_-]+)+";

  public RestServicePrefix() {
    this(true);
  }

  public RestServicePrefix(boolean useDefaultS3) {
    mServicePrefixes = new ArrayList<>();
    if (useDefaultS3) {
      mServicePrefixes.add(new ServicePrefix(PROXY_S3_REST, ROOT_PREFIX, false));
    }
  }

  public void put(String service, String prefix) {
    if (isValidPrefix(prefix)) {
      if (isS3RestService(service)) {
        mServicePrefixes.add(new ServicePrefix(service, prefix, false));
      } else {
        boolean isConflict = checkConflict(prefix);
        mServicePrefixes.add(new ServicePrefix(service, prefix, isConflict));
      }
    } else {
      LOG.warn("The prefix [{}] for [{}] rest handler is invalid path prefix.", prefix, service);
    }
  }

  public boolean isValidPrefix(String prefix) {
    if (prefix == null || (!prefix.matches(PATH_PATTERN) && !ROOT_PREFIX.equals(prefix))) {
      return false;
    }
    return true;
  }

  /**
   *
   * @param prefix
   * @return return false if there is a conflict
   */
  public boolean checkConflict(String prefix) {
    for (ServicePrefix servicePrefix : mServicePrefixes) {
      String p = servicePrefix.getPrefix();
      if (p.equals(prefix) || p.startsWith(prefix) || prefix.startsWith(p)) {
        if (!isS3RestService(servicePrefix.getService())) {
          servicePrefix.setConflict(true);
        }
        return true;
      }
    }
    return false;
  }

  /**
   * Register handler for valid rest service.
   * @param action action to perform on the elements
   */
  public void registerService(BiConsumer<String, String> action) {
    mServicePrefixes.stream().filter(s -> !s.isConflict())
        .forEach(s -> action.accept(s.getService(), s.getPrefix()));
    mServicePrefixes.stream().filter(ServicePrefix::isConflict).forEach(servicePrefix -> {
      LOG.warn("Failed register [{}] rest handler with conflicting path prefix [{}]",
          servicePrefix.getService(), servicePrefix.getPrefix());
    });
  }

  public boolean isS3RestService(String service) {
    return PROXY_S3_REST.equals(service);
  }

  public static class ServicePrefix {
    private String mService;
    private String mPrefix;
    private boolean mIsConflict;

    public ServicePrefix(String service, String prefix, boolean isConflict) {
      mService = service;
      mPrefix = prefix;
      mIsConflict = isConflict;
    }

    public String getPrefix() {
      return mPrefix;
    }

    public String getService() {
      return mService;
    }

    public void setConflict(boolean isConflict) {
      mIsConflict = isConflict;
    }

    public boolean isConflict() {
      return mIsConflict;
    }
  }
}
