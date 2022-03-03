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

package alluxio.util;

import alluxio.util.MD5Utils.MD5Hash;
import alluxio.util.io.IOUtils;

import com.google.common.base.Charsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MD5FileUtils {
  private static final Logger LOG = LoggerFactory.getLogger(MD5FileUtils.class);
  public static final String MD5_SUFFIX = ".md5";
  private static final Pattern LINE_REGEX =
            Pattern.compile("([0-9a-f]{32}) [ \\*](.+)");

  /**
   * Read the md5 file stored alongside the given data file
   * and match the md5 file content.
   * @param md5File the file containing data
   * @return a matcher with two matched groups
   * where group(1) is the md5 string and group(2) is the data file path.
   */
  private static Matcher readStoredMd5(File md5File) throws IOException {
    BufferedReader reader =
                new BufferedReader(new InputStreamReader(new FileInputStream(
                        md5File), Charsets.UTF_8));
    String md5Line;
    try {
      md5Line = reader.readLine();
      if (md5Line == null) {
        md5Line = "";
      }
      md5Line = md5Line.trim();
    } catch (IOException ioe) {
      throw new IOException("Error reading md5 file at " + md5File, ioe);
    } finally {
      IOUtils.cleanupWithLogger(LOG, reader);
    }

    Matcher matcher = LINE_REGEX.matcher(md5Line);
    if (!matcher.matches()) {
      throw new IOException("Invalid MD5 file " + md5File + ": the content \""
                    + md5Line + "\" does not match the expected pattern.");
    }
    return matcher;
  }

  /**
   * Read the md5 checksum stored alongside the given data file.
   * @param dataFile the file containing data
   * @return the checksum stored in dataFile.md5
   */
  public static MD5Hash readStoredMd5ForFile(File dataFile) throws IOException {
    final File md5File = getDigestFileForFile(dataFile);
    if (!md5File.exists()) {
      return null;
    }

    final Matcher matcher = readStoredMd5(md5File);
    String storedHash = matcher.group(1);
    File referencedFile = new File(matcher.group(2));

    // Sanity check: Make sure that the file referenced in the .md5 file at
    // least has the same name as the file we expect
    if (!referencedFile.getName().equals(dataFile.getName())) {
      throw new IOException("MD5 file at " + md5File + " references file named "
              + referencedFile.getName() + " but we expected it to reference "
              + dataFile);
    }
    return new MD5Hash(storedHash);
  }

  /**
   * Read dataFile and compute its MD5 checksum.
   *
   * @param dataFile input data file
   * @return a instance of MD5Hash
   */
  public static MD5Hash computeMd5ForFile(File dataFile) throws IOException {
    InputStream in = new FileInputStream(dataFile);
    try {
      MessageDigest digester = MD5Hash.getDigester();
      DigestInputStream dis = new DigestInputStream(in, digester);
      IOUtils.copyBytes(dis, new IOUtils.NullOutputStream(), 128 * 1024);

      return new MD5Hash(digester.digest());
    } finally {
      IOUtils.closeStream(in);
    }
  }

  /**
   *
   * @param file input file
   * @return a reference to the file with .md5 suffix that will
   * contain the md5 checksum for the given data file.
   */
  public static File getDigestFileForFile(File file) {
    return new File(file.getParentFile(), file.getName() + MD5_SUFFIX);
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
