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
import alluxio.conf.AlluxioConfiguration;

/**
 * Fuse Auth Policy Interface.
 */
public interface AuthPolicy {
  /**
   * Sets user and group if needed.
   *
   * @param fileSystem the file system
   * @param uri the path uri
   */
  void setUserGroupIfNeeded(FileSystem fileSystem, AlluxioURI uri) throws Exception;

  /**
   *
   * @param conf the configuration
   * @return the file system
   * @throws Exception
   */
  FileSystem getFileSystemByUser(AlluxioConfiguration conf) throws Exception;
}
