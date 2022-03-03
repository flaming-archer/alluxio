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

package alluxio.util.io;

import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

public class IOUtils {

  /**
   * Copies from one stream to another.
   *
   * @param in InputStrem to read from
   * @param out OutputStream to write to
   * @param buffSize the size of the buffer
   */
  public static void copyBytes(InputStream in, OutputStream out, int buffSize)
            throws IOException {
    PrintStream ps = out instanceof PrintStream ? (PrintStream) out : null;
    byte[] buf = new byte[buffSize];
    int bytesRead = in.read(buf);
    while (bytesRead >= 0) {
      out.write(buf, 0, bytesRead);
      if ((ps != null) && ps.checkError()) {
        throw new IOException("Unable to write to output stream.");
      }
      bytesRead = in.read(buf);
    }
  }

  /**
   * Closes the stream ignoring {@link Throwable}.
   * Must only be called in cleaning up from exception handlers.
   *
   * @param stream the Stream to close
   */
  public static void closeStream(java.io.Closeable stream) {
    if (stream != null) {
      cleanupWithLogger(null, stream);
    }
  }

  /**
   * Close the Closeable objects and <b>ignore</b> any {@link Throwable} or
   * null pointers. Must only be used for cleanup in exception handlers.
   *
   * @param logger the log to record problems to at debug level. Can be null
   * @param closeables the objects to close
   */
  public static void cleanupWithLogger(Logger logger,
                                       java.io.Closeable... closeables) {
    for (java.io.Closeable c : closeables) {
      if (c != null) {
        try {
          c.close();
        } catch (Throwable e) {
          if (logger != null) {
            logger.debug("Exception in closing {}", c, e);
          }
        }
      }
    }
  }

  /**
   * The /dev/null of OutputStreams.
   */
  public static class NullOutputStream extends OutputStream {
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
    }

    @Override
    public void write(int b) throws IOException {
    }
  }
}
