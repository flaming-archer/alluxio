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

import alluxio.bcrypt.BCryptPasswordEncoder;
import alluxio.bcrypt.PasswordEncoder;
import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.InstancedConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.security.authentication.AuthenticationProvider;
import alluxio.util.ConfigurationUtils;
import alluxio.util.Timer;

import com.google.common.base.Ticker;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.Callable;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Executors;

public class RpcPasswordAuthenticationProvider implements AuthenticationProvider {
  private static final Logger LOG =
          LoggerFactory.getLogger(RpcPasswordAuthenticationProvider.class);

  private final RpcPasswordMappingServiceProvider mRpcPwdMappingProvider;

  private final LoadingCache<String, RpcPassword> mCache;

  private final long mCacheTimeout;
  private final long mNegativeCacheTimeout;
  private final long mWarningDeltaMs;
  private final Timer mTimer;
  private Set<String> mNegativeCache;
  private final boolean mReloadRpcPasswordInBackground;
  private final int mReloadRpcPasswordThreadCount;

  private final AtomicLong mBackgroundRefreshSuccess = new AtomicLong(0);
  private final AtomicLong mBackgroundRefreshException = new AtomicLong(0);
  private final AtomicLong mBackgroundRefreshQueued = new AtomicLong(0);
  private final AtomicLong mBackgroundRefreshRunning = new AtomicLong(0);

  private PasswordEncoder mPasswordEncoder;
  private Cache<PasswordMatchEntry, Boolean> mPasswordMatchedCache;

  public RpcPasswordAuthenticationProvider(AlluxioConfiguration conf) {
    this(conf, new Timer());
  }

  public RpcPasswordAuthenticationProvider(AlluxioConfiguration conf, final Timer timer) {
    mRpcPwdMappingProvider = RpcPasswordMappingServiceProvider.Factory.create(conf);

    mCacheTimeout = conf.getLong(PropertyKey.SECURITY_RPC_PASSWORD_CACHE_SECS) * 1000;
    mNegativeCacheTimeout =
            conf.getLong(PropertyKey.SECURITY_RPC_PASSWORD_NEGATIVE_CACHE_SECS) * 1000;
    mWarningDeltaMs = conf.getLong(PropertyKey.SECURITY_RPC_PASSWORD_CACHE_WARN_AFTER_MS);
    mReloadRpcPasswordInBackground =
            conf.getBoolean(PropertyKey.SECURITY_RPC_PASSWORD_CACHE_BACKGROUND_RELOAD);
    mReloadRpcPasswordThreadCount =
            conf.getInt(PropertyKey.SECURITY_RPC_PASSWORD_CACHE_BACKGROUND_RELOAD_THREADS);

    mTimer = timer;
    mCache = CacheBuilder.newBuilder().refreshAfterWrite(mCacheTimeout, TimeUnit.MILLISECONDS)
            .ticker(new TimerToTickerAdapter(timer))
            .expireAfterWrite(10 * mCacheTimeout, TimeUnit.MILLISECONDS)
            .build(new RpcPasswordCacheLoader());

    mPasswordEncoder = new BCryptPasswordEncoder();
    mPasswordMatchedCache = CacheBuilder.newBuilder()
            .expireAfterWrite(conf.getInt(
                    PropertyKey.SECURITY_RPC_PASSWORD_MATCH_CACHE_MINUTE), TimeUnit.MINUTES)
            .maximumSize(conf.getInt(
                    PropertyKey.SECURITY_RPC_PASSWORD_MATCH_CACHE_SIZE))
            .build();

    if (mNegativeCacheTimeout > 0) {
      Cache<String, Boolean> tempMap = CacheBuilder.newBuilder()
              .expireAfterWrite(mNegativeCacheTimeout, TimeUnit.MILLISECONDS)
              .ticker(new TimerToTickerAdapter(timer)).build();
      mNegativeCache = Collections.newSetFromMap(tempMap.asMap());
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("Rpc Password mapping impl=" + mRpcPwdMappingProvider.getClass().getName()
              + "; cacheTimeout=" + mCacheTimeout + "; warningDeltaMs=" + mWarningDeltaMs);
    }
  }

  @Override
  public void authenticate(String userName, String password) throws AuthenticationException {
    try {
      if (StringUtils.isNotEmpty(userName)) {
        if (!isBypassUser(userName)) {
          String hashedRpcPassword = getRpcPassword(userName);
          if (StringUtils.isEmpty(hashedRpcPassword)) {
            throw new SaslException("No rpcPassword record on server side for user: "
                    + userName);
          }
          if (StringUtils.isEmpty(password)) {
            throw new SaslException("Rpc password empty from client side "
                    + "for user: " + userName);
          }
          Callable<Boolean> passwordMatchedLoader = new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {
              return mPasswordEncoder.matches(password, hashedRpcPassword);
            }
          };
          if (!mPasswordMatchedCache.get(new PasswordMatchEntry(userName,
                  password, hashedRpcPassword), passwordMatchedLoader)) {
            throw new SaslException("Rpc password Authentication failed for user: "
                    + userName);
          }
        }
      } else {
        throw new AuthenticationException("Illegal user error");
      }
    } catch (AuthenticationException e) {
      throw e;
    } catch (ExecutionException e) {
      LOG.error("Get Authentication error from cache for user: " + userName, e);
    } catch (IOException e) {
      throw new AuthenticationException(e.getMessage());
    }
  }

  private boolean isNegativeCacheEnabled() {
    return mNegativeCacheTimeout > 0;
  }

  private IOException noRpcPasswordForUser(String user) {
    return new IOException("No rpc password found for user " + user);
  }

  /**
   * Get the group memberships of a given user.
   * If the user's group is not cached, this method may block.
   *
   * @param user User's name
   * @return the group memberships of the user
   * @throws IOException if user does not exist
   */
  public String getRpcPassword(final String user) throws IOException {
    // Check the negative cache first
    if (isNegativeCacheEnabled()) {
      if (mNegativeCache.contains(user)) {
        throw noRpcPasswordForUser(user);
      }
    }

    try {
      return mCache.get(user).getRpcPassword();
    } catch (ExecutionException e) {
      throw new IOException(e.getCause());
    }
  }

  /**
   * Check if the given user is a bypass user.
   *
   * @param user User's name
   * @return if it's a bypass user
   * @throws IOException if user does not exist
   */
  public boolean isBypassUser(final String user) throws IOException {
    // Check the negative cache first
    if (isNegativeCacheEnabled()) {
      if (mNegativeCache.contains(user)) {
        throw noRpcPasswordForUser(user);
      }
    }
    try {
      return mCache.get(user).isBypass();
    } catch (ExecutionException e) {
      throw new IOException(e.getCause());
    }
  }

  public long getBackgroundRefreshSuccess() {
    return mBackgroundRefreshSuccess.get();
  }

  public long getBackgroundRefreshException() {
    return mBackgroundRefreshException.get();
  }

  public long getBackgroundRefreshQueued() {
    return mBackgroundRefreshQueued.get();
  }

  public long getBackgroundRefreshRunning() {
    return mBackgroundRefreshRunning.get();
  }

  /**
   * Convert millisecond times from hadoop's timer to guava's nanosecond ticker.
   */
  private static class TimerToTickerAdapter extends Ticker {
    private Timer mTimer;

    public TimerToTickerAdapter(Timer timer) {
      mTimer = timer;
    }

    @Override
    public long read() {
      final long NANOSECONDS_PER_MS = 1000000;
      return mTimer.monotonicNow() * NANOSECONDS_PER_MS;
    }
  }

  /**
   * Deals with loading data into the cache.
   */
  private class RpcPasswordCacheLoader extends CacheLoader<String, RpcPassword> {

    private ListeningExecutorService mExecutorService;

    RpcPasswordCacheLoader() {
      if (mReloadRpcPasswordInBackground) {
        ThreadFactory threadFactory = new ThreadFactoryBuilder()
                .setNameFormat("RpcPassword-Cache-Reload")
                .setDaemon(true).build();
        // With coreThreadCount == maxThreadCount we effectively
        // create a fixed size thread pool. As allowCoreThreadTimeOut
        // has been set, all threads will die after 60 seconds of non use
        ThreadPoolExecutor mParentExecutor = new ThreadPoolExecutor(mReloadRpcPasswordThreadCount,
                mReloadRpcPasswordThreadCount, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(), threadFactory);
        mParentExecutor.allowCoreThreadTimeOut(true);
        mExecutorService = MoreExecutors.listeningDecorator(mParentExecutor);
      }
    }

    /**
     * This method will block if a cache entry doesn't exist, and
     * any subsequent requests for the same user will wait on this
     * request to return. If a user already exists in the cache,
     * and when the key expires, the first call to reload the key
     * will block, but subsequent requests will return the old
     * value until the blocking thread returns.
     * If reloadGroupsInBackground is true, then the thread that
     * needs to refresh an expired key will not block either. Instead
     * it will return the old cache value and schedule a background
     * refresh
     *
     * @param user key of cache
     * @return List of groups belonging to user
     * @throws IOException to prevent caching negative entries
     */
    @Override
    public RpcPassword load(String user) throws Exception {
      RpcPassword rpcPassword = fetchRpcPassword(user);
      if (rpcPassword.isEmpty()) {
        if (isNegativeCacheEnabled()) {
          mNegativeCache.add(user);
        }

        // We throw here to prevent Cache from retaining an empty password
        throw noRpcPasswordForUser(user);
      }
      return rpcPassword;
    }

    /**
     * Override the reload method to provide an asynchronous implementation. If
     * reloadGroupsInBackground is false, then this method defers to the super
     * implementation, otherwise is arranges for the cache to be updated later
     */
    @Override
    public ListenableFuture<RpcPassword> reload(final String key,
                                                RpcPassword oldValue) throws Exception {
      if (!mReloadRpcPasswordInBackground) {
        return super.reload(key, oldValue);
      }

      mBackgroundRefreshQueued.incrementAndGet();
      ListenableFuture<RpcPassword> listenableFuture =
                      mExecutorService.submit(new Callable<RpcPassword>() {
                        @Override
                        public RpcPassword call() throws Exception {
                          mBackgroundRefreshQueued.decrementAndGet();
                          mBackgroundRefreshRunning.incrementAndGet();
                          RpcPassword result = load(key);
                          return result;
                        }
                      });
      Futures.addCallback(listenableFuture, new FutureCallback<RpcPassword>() {
        @Override
        public void onSuccess(RpcPassword result) {
          mBackgroundRefreshSuccess.incrementAndGet();
          mBackgroundRefreshRunning.decrementAndGet();
        }

        @Override
        public void onFailure(Throwable t) {
          mBackgroundRefreshException.incrementAndGet();
          mBackgroundRefreshRunning.decrementAndGet();
        }
      }, Executors.newSingleThreadExecutor());
      return listenableFuture;
    }

    /**
     * Queries impl for rpc password belonging to the user. This could involve I/O and take awhile.
     */
    private RpcPassword fetchRpcPassword(String user) throws IOException {
      long startMs = mTimer.monotonicNow();
      String rpcPassword = mRpcPwdMappingProvider.getRpcPassword(user);
      boolean isBypass = mRpcPwdMappingProvider.isBypassUser(user);
      long endMs = mTimer.monotonicNow();
      long deltaMs = endMs - startMs;
      if (deltaMs > mWarningDeltaMs) {
        LOG.warn("Potential performance problem: getRpcPassword(user=" + user + ") "
                + "took " + deltaMs + " milliseconds.");
      }
      return new RpcPassword(rpcPassword, isBypass);
    }
  }

  /**
   * Refresh all user-to-rpcPassword mappings.
   */
  public void refresh() throws IOException {
    LOG.info("clearing userToRpcPasswordMap cache");
    mCache.invalidateAll();
    if (isNegativeCacheEnabled()) {
      mNegativeCache.clear();
    }
    mRpcPwdMappingProvider.cacheRefresh(true);
  }

  private static RpcPasswordAuthenticationProvider sRpcPassword = null;

  /**
   * Get the RpcPassword being used to map user-to-rpcPassword.
   *
   * @return the rpcPassword being used to map user-to-rpcPassword
   */
  public static RpcPasswordAuthenticationProvider getUserToRpcPasswordMappingService() {
    return getUserToRpcPasswordMappingService(
            new InstancedConfiguration(ConfigurationUtils.defaults()));
  }

  /**
   * Get the RpcPassword being used to map user-to-rpcPassword.
   *
   * @param conf
   * @return the rpcPassword being used to map user-to-rpcPassword
   */
  public static synchronized RpcPasswordAuthenticationProvider getUserToRpcPasswordMappingService(
          AlluxioConfiguration conf) {
    if (sRpcPassword == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(" Creating new RpcPassword object");
      }
      sRpcPassword = new RpcPasswordAuthenticationProvider(conf);
    }
    return sRpcPassword;
  }

  private static class PasswordMatchEntry {
    private String mUsername;
    private String mRawPassword;
    private String mHashedPassword;

    public PasswordMatchEntry(String username, String rawPassword,
                              String hashedPassword) {
      mUsername = username;
      mRawPassword = rawPassword;
      mHashedPassword = hashedPassword;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      PasswordMatchEntry that = (PasswordMatchEntry) o;
      return Objects.equals(mUsername, that.mUsername)
              && Objects.equals(mRawPassword, that.mRawPassword)
              && Objects.equals(mHashedPassword, that.mHashedPassword);
    }

    @Override
    public int hashCode() {
      return Objects.hash(mUsername, mRawPassword, mHashedPassword);
    }
  }
}
