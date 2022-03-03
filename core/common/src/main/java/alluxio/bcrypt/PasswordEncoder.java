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

package alluxio.bcrypt;

/**
 * Service interface for encoding passwords.
 *
 * The preferred implementation is {@code BCryptPasswordEncoder}.
 *
 * @author Keith Donald
 */
public interface PasswordEncoder {
  /**
   * Encode the raw password. Generally, a good encoding algorithm applies a SHA-1 or
   * greater hash combined with an 8-byte or greater randomly generated salt.
   *
   * @param rawPassword the raw password to encode and match
   * @return the encoded string
   */
  String encode(CharSequence rawPassword);

  /**
   * Verify the encoded password obtained from storage matches the submitted raw
   * password after it too is encoded. Returns true if the passwords match, false if
   * they do not. The stored password itself is never decoded.
   *
   * @param rawPassword the raw password to encode and match
   * @param encodedPassword the encoded password from storage to compare with
   * @return true if the raw password, after encoding, matches the encoded password from
   * storage
   */
  boolean matches(CharSequence rawPassword, String encodedPassword);

  /**
   * Returns true if the encoded password should be encoded again for better security,
   * else false. The default implementation always returns false.
   * @param encodedPassword the encoded password to check
   * @return true if the encoded password should be encoded again for better security,
   * else false.
   */
  boolean upgradeEncoding(String encodedPassword);
}
