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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class MD5Utils {
  /** Construct a hash value for a String.
   *
   * @param string string that need to be encrypted
   * @return a new instance of {@link MD5Hash}
   */
  public static MD5Hash digest(String string) {
    return digest(string.getBytes());
  }

  /** Construct a hash value for a byte array.
   *
   * @param data bytes that need to be encrypted
   * @return a new instance of {@link MD5Hash}
   */
  public static MD5Hash digest(byte[] data) {
    return digest(data, 0, data.length);
  }

  /** Construct a hash value for a byte array.
   *
   * @param data bytes that need to be encrypted
   * @param start the starting value to use
   * @param len the length value to use
   * @return a new instance of {@link MD5Hash}
   * */
  public static MD5Hash digest(byte[] data, int start, int len) {
    byte[] digest;
    MessageDigest digester = getDigester();
    digester.update(data, start, len);
    digest = digester.digest();
    return new MD5Hash(digest);
  }

  /**
   * Create a thread local MD5 digester.
   *
   * @return a new instance of {@link MessageDigest}
   */
  public static MessageDigest getDigester() {
    MessageDigest digester = MD5Hash.DIGESTER_FACTORY.get();
    digester.reset();
    return digester;
  }

  public static class MD5Hash {
    public static final int MD5_LEN = 16;
    private static final ThreadLocal<MessageDigest> DIGESTER_FACTORY =
        new ThreadLocal<MessageDigest>() {
          @Override
          protected MessageDigest initialValue() {
            try {
              return MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
              throw new RuntimeException(e);
            }
          }
        };

    private byte[] mDigest;

    /** Constructs an MD5Hash. */
    public MD5Hash() {
      mDigest = new byte[MD5_LEN];
    }

    /** Constructs an MD5Hash from a hex string.
     *
     * @param hex string
     */
    public MD5Hash(String hex) {
      setDigest(hex);
    }

    /** Constructs an MD5Hash with a specified value.
     *
     * @param digest bytes
     * */
    public MD5Hash(byte[] digest) {
      mDigest = new byte[MD5_LEN];
      if (digest.length != MD5_LEN) {
        throw new IllegalArgumentException("Wrong length: " + digest.length);
      }
      for (int i = 0; i < MD5_LEN; i++) {
        mDigest[i] = digest[i];
      }
    }

    /** Copy the contents of another instance into this instance.
     *
     * @param that MD5Hash instance
     */
    public void set(MD5Hash that) {
      System.arraycopy(that.mDigest, 0, this.mDigest, 0, MD5_LEN);
    }

    /** Returns the digest bytes.
     *
     * @return digest bytes
     * */
    public byte[] getDigest() {
      return mDigest;
    }

    /** Construct a hash value for a byte array.
     *
     * @param data bytes
     * @return instance of {@link MD5Hash}
     */
    public static MD5Hash digest(byte[] data) {
      return digest(data, 0, data.length);
    }

    /** Construct a hash value for the content from the InputStream.
     *
     * @param in InputStream instance
     * @return instance of {@link MD5Hash}
     */
    public static MD5Hash digest(InputStream in) throws IOException {
      final byte[] buffer = new byte[4 * 1024];

      final MessageDigest digester = getDigester();
      for (int n; (n = in.read(buffer)) != -1; ) {
        digester.update(buffer, 0, n);
      }
      return new MD5Hash(digester.digest());
    }

    /** Construct a hash value for a byte array.
     *
     * @param data bytes that need to be encrypted
     * @param start the starting value to use
     * @param len the length value to use
     * @return a new instance of {@link MD5Hash}
     * */
    public static MD5Hash digest(byte[] data, int start, int len) {
      byte[] digest;
      MessageDigest digester = getDigester();
      digester.update(data, start, len);
      digest = digester.digest();
      return new MD5Hash(digest);
    }

    /** Construct a hash value for a String.
     *
     * @param string the string to be hash
     * @return instance of {@link MD5Hash}
     */
    public static MD5Hash digest(String string) {
      return digest(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Create a thread local MD5 digester.
     *
     * @return instance of {@link MessageDigest}
     */
    public static MessageDigest getDigester() {
      MessageDigest digester = DIGESTER_FACTORY.get();
      digester.reset();
      return digester;
    }

    /** Construct a half-sized version of this MD5.  Fits in a long
     *
     * @return a half-sized version of this MD5
     */
    public long halfDigest() {
      long value = 0;
      for (int i = 0; i < 8; i++) {
        value |= ((mDigest[i] & 0xffL) << (8 * (7 - i)));
      }
      return value;
    }

   /**
    * Return a 32-bit digest of the MD5.
    * @return the first 4 bytes of the md5
    */
    public int quarterDigest() {
      int value = 0;
      for (int i = 0; i < 4; i++) {
        value |= ((mDigest[i] & 0xff) << (8 * (3 - i)));
      }
      return value;
    }

    /** Returns true iff <code>o</code> is an MD5Hash whose digest contains the
     * same values.
     */
    @Override
    public boolean equals(Object o) {
      if (!(o instanceof MD5Hash)) {
        return false;
      }
      MD5Hash other = (MD5Hash) o;
      return Arrays.equals(this.mDigest, other.mDigest);
    }

    /** Returns a hash code value for this object.
     * Only uses the first 4 bytes, since md5s are evenly distributed.
     */
    @Override
    public int hashCode() {
      return quarterDigest();
    }

    private static final char[] HEX_DIGITS =
        {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /** Returns a string representation of this object. */
    @Override
    public String toString() {
      StringBuilder buf = new StringBuilder(MD5_LEN * 2);
      for (int i = 0; i < MD5_LEN; i++) {
        int b = mDigest[i];
        buf.append(HEX_DIGITS[(b >> 4) & 0xf]);
        buf.append(HEX_DIGITS[b & 0xf]);
      }
      return buf.toString();
    }

    /** Sets the digest value from a hex string.
     *
     * @param hex
     */
    public void setDigest(String hex) {
      if (hex.length() != MD5_LEN * 2) {
        throw new IllegalArgumentException("Wrong length: " + hex.length());
      }
      byte[] digest = new byte[MD5_LEN];
      for (int i = 0; i < MD5_LEN; i++) {
        int j = i << 1;
        digest[i] = (byte) (charToNibble(hex.charAt(j)) << 4
                | charToNibble(hex.charAt(j + 1)));
      }
      mDigest = digest;
    }

    private static final int charToNibble(char c) {
      if (c >= '0' && c <= '9') {
        return c - '0';
      } else if (c >= 'a' && c <= 'f') {
        return 0xa + (c - 'a');
      } else if (c >= 'A' && c <= 'F') {
        return 0xA + (c - 'A');
      } else {
        throw new RuntimeException("Not a hex character: " + c);
      }
    }
  }
}
