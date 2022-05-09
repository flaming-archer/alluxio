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

package alluxio.web;

import alluxio.StreamCache;
import alluxio.client.file.FileSystem;
import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.InstancedConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.conf.ServerConfiguration;
import alluxio.proxy.ProxyProcess;
import alluxio.proxy.RestServicePrefix;
import alluxio.proxy.s3.CompleteMultipartUploadHandler;
import alluxio.util.io.PathUtils;

import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;

import java.net.InetSocketAddress;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;
import javax.servlet.ServletException;

/**
 * The Alluxio proxy web server.
 */
@NotThreadSafe
public final class ProxyWebServer extends WebServer {

  public static final String ALLUXIO_PROXY_SERVLET_RESOURCE_KEY = "Alluxio Proxy";
  public static final String FILE_SYSTEM_SERVLET_RESOURCE_KEY = "File System";
  public static final String STREAM_CACHE_SERVLET_RESOURCE_KEY = "Stream Cache";
  public static final String SERVER_CONFIGURATION_RESOURCE_KEY = "Server Configuration";
  public static final String BASE_PACKAGE = "alluxio.proxy";

  private FileSystem mFileSystem;

  private InstancedConfiguration mSConf;

  private RestServicePrefix mServicePrefix;

  /**
   * Creates a new instance of {@link ProxyWebServer}.
   *
   * @param serviceName the service name
   * @param address the service address
   * @param proxyProcess the Alluxio proxy process
   */
  public ProxyWebServer(String serviceName, InetSocketAddress address,
      final ProxyProcess proxyProcess) {
    super(serviceName, address);

    mSConf = ServerConfiguration.global();
    mFileSystem = FileSystem.Factory.create(mSConf);

    initRestServiceInfo(mSConf);

    mServicePrefix.registerService((restType, prefix) -> {
      ServletHolder servletHolder = getServlet(restType, proxyProcess);
      mServletContextHandler
          .addServlet(servletHolder, PathUtils.concatPath(prefix, "*"));
    });

    addHandler(new CompleteMultipartUploadHandler(mFileSystem));
  }

  public void initRestServiceInfo(AlluxioConfiguration conf) {
    List<String> proxyServices = conf.getList(PropertyKey.PROXY_REST_HANDLER, ",");
    if (proxyServices.size() == 1 && "s3".equals(proxyServices.get(0))
        && !conf.isSet(PropertyKey.Template.PROXY_REST_PREFIX.format("s3"))) {
      mServicePrefix = new RestServicePrefix();
    } else {
      mServicePrefix = new RestServicePrefix(false);
      for (int i = 0; i < proxyServices.size(); i++) {
        String restTypeName = proxyServices.get(i);
        String value = null;
        if (conf.isSet(PropertyKey.Template.PROXY_REST_PREFIX.format(restTypeName))) {
          value = conf.get(PropertyKey.Template.PROXY_REST_PREFIX.format(restTypeName));
          mServicePrefix.put(restTypeName, value);
        }
      }
    }
  }

  public ServletHolder getServlet(String restType, ProxyProcess proxyProcess) {
    ResourceConfig config = new ResourceConfig()
        .packages(String.format("%s.%s", BASE_PACKAGE, restType))
        .register(JacksonProtobufObjectMapperProvider.class);
    ServletContainer servlet = new ServletContainer(config) {
      private static final long serialVersionUID = 7756010860672831556L;

      @Override
      public void init() throws ServletException {
        super.init();
        getServletContext().setAttribute(ALLUXIO_PROXY_SERVLET_RESOURCE_KEY, proxyProcess);
        getServletContext().setAttribute(FILE_SYSTEM_SERVLET_RESOURCE_KEY, mFileSystem);
        getServletContext().setAttribute(STREAM_CACHE_SERVLET_RESOURCE_KEY,
            new StreamCache(ServerConfiguration.getMs(PropertyKey.PROXY_STREAM_CACHE_TIMEOUT_MS)));
        getServletContext().setAttribute(SERVER_CONFIGURATION_RESOURCE_KEY, mSConf);
      }
    };
    ServletHolder servletHolder = new ServletHolder(restType, servlet);
    return servletHolder;
  }

  @Override
  public void stop() throws Exception {
    mFileSystem.close();
    super.stop();
  }
}
