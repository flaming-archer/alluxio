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

import java.util.Locale;

public class StringUtils {

  /** Same as byteToHexString(bytes, 0, bytes.length).
   *
   * @param bytes input byte array
   * @return the hex string
   */
  public static String byteToHexString(byte[] bytes) {
    return byteToHexString(bytes, 0, bytes.length);
  }

  /** Convert a byte array to hex string.
   *
   * @param bytes input byte array
   * @param start the start value to use
   * @param end the end value to use
   * @return the hex string
   */
  public static String byteToHexString(byte[] bytes, int start, int end) {
    if (bytes == null) {
      throw new IllegalArgumentException("bytes == null");
    }
    StringBuilder s = new StringBuilder();
    for (int i = start; i < end; i++) {
      s.append(format("%02x", bytes[i]));
    }
    return s.toString();
  }

  /** The same as String.format(Locale.ENGLISH, format, objects).
   *
   * @param format a format string
   * @param objects   Arguments referenced by the format specifiers in the format string
   * @return a formatted string
   */
  public static String format(final String format, final Object... objects) {
    return String.format(Locale.ENGLISH, format, objects);
  }
}
