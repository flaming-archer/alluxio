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

package alluxio.proxy.s3.auth;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.proxy.s3.S3Exception;
import alluxio.proxy.s3.signature.AuthorizationV4Validator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class BasedOnRAMAuthenticator implements Authenticator {

  private static final Logger LOG = LoggerFactory.getLogger(BasedOnRAMAuthenticator.class);

  private String mPasswordServiceUrl;
  private String mPasswordServiceToken;
  private int mRefreshAfterWriteMin;
  private int mExpireAfterWriteMin;
  private int mCacheSize;
  private LoadingCache<String, String> mCache;

  @Override
  public void init(AlluxioConfiguration conf) {
    Authenticator.super.init(conf);
    mPasswordServiceUrl = conf.get(PropertyKey.S3_REST_AUTHENTICATOR_RAM_PASSWORD_SERVICE_URL);
    if (mPasswordServiceUrl == null || mPasswordServiceUrl.isEmpty()) {
      throw new RuntimeException("BasedOnRAMAuthenticator Password Service URL not specified");
    }
    mPasswordServiceUrl = formatURL(mPasswordServiceUrl);
    mPasswordServiceToken = conf.get(PropertyKey.S3_REST_AUTHENTICATOR_RAM_PASSWORD_SERVICE_TOKEN);
    if (mPasswordServiceToken == null || mPasswordServiceToken.isEmpty()) {
      throw new RuntimeException("BasedOnRAMAuthenticator Password Service Token not specified");
    }

    mCacheSize = conf.getInt(PropertyKey.S3_REST_AUTHENTICATOR_RAM_CACHE_SIZE);
    mRefreshAfterWriteMin =
        conf.getInt(PropertyKey.S3_REST_AUTHENTICATOR_RAM_CACHE_REFRESH_TIMEOUT);
    mExpireAfterWriteMin = conf.getInt(PropertyKey.S3_REST_AUTHENTICATOR_RAM_CACHE_EXPIRE_TIMEOUT);

    CacheLoader<String, String> loader;
    loader = new CacheLoader<String, String>() {
      @Override
      public String load(String username) throws Exception {
        return getPassword(username);
      }
    };
    mCache = CacheBuilder.newBuilder()
            .refreshAfterWrite(mRefreshAfterWriteMin, TimeUnit.MINUTES)
            .expireAfterWrite(mExpireAfterWriteMin, TimeUnit.MINUTES)
            .maximumSize(mCacheSize)
            .build(loader);
  }

  @Override
  public boolean isAuthenticated(AwsAuthInfo authInfo) throws S3Exception {
    String password = null;
    try {
      password = mCache.get(authInfo.getAccessID());
    } catch (ExecutionException e) {
      LOG.error("Error from loading cache: " + e.getMessage());
    }
    return AuthorizationV4Validator.validateRequest(
            authInfo.getStringTosSign(),
            authInfo.getSignature(),
            password);
  }

  private String getPassword(String userName) {
    BufferedReader in = null;
    try {
      URL url = new URL(mPasswordServiceUrl + userName);
      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("X-DMP-Authorization", mPasswordServiceToken);
      conn.setRequestProperty("accept", "application/json");
      conn.connect();

      //Getting the response code
      int responseCode = conn.getResponseCode();

      if (responseCode != HttpURLConnection.HTTP_OK) {
        String readLine;
        in = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
        StringBuffer response = new StringBuffer();
        while ((readLine = in.readLine()) != null) {
          response.append(readLine);
        }

        LOG.error("Error from password service: " + response);
      } else {
        String readLine;
        in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuffer response = new StringBuffer();
        while ((readLine = in.readLine()) != null) {
          response.append(readLine);
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.toString());
        return jsonNode.get("data").asText();
      }
    }  catch (Exception e) {
      LOG.error("Error from password service: " + e.getMessage());
    } finally {
      try {
        in.close();
      } catch (Exception ex) {
        LOG.error("Error from closing reader stream: " + ex.getMessage());
      }
    }
    return null;
  }

  private String formatURL(String url) {
    if (!url.endsWith("/")) {
      return url + "/";
    }
    return url;
  }
}
