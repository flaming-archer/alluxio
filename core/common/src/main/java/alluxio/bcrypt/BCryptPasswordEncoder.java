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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Implementation of PasswordEncoder that uses the BCrypt strong hashing function. Clients
 * can optionally supply a "version" ($2a, $2b, $2y) and a "strength" (a.k.a. log rounds in BCrypt)
 * and a SecureRandom instance. The larger the strength parameter the more work will have to be done
 * (exponentially) to hash the passwords. The default value is 10.
 *
 * @author Dave Syer
 */
public class BCryptPasswordEncoder implements PasswordEncoder {
  private static final Logger LOG = LoggerFactory.getLogger(BCryptPasswordEncoder.class);
  private Pattern mBcryptPattern = Pattern
            .compile("\\A\\$2(a|y|b)?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}");

  private final int mStrength;
  private final BCryptVersion mVersion;

  private final SecureRandom mRandom;

  public BCryptPasswordEncoder() {
    this(-1);
  }

  /**
   * @param strength the log rounds to use, between 4 and 31
   */
  public BCryptPasswordEncoder(int strength) {
    this(strength, null);
  }

  /**
   * @param version the version of bcrypt, can be 2a,2b,2y
   */
  public BCryptPasswordEncoder(BCryptVersion version) {
    this(version, null);
  }

  /**
   * @param version the version of bcrypt, can be 2a,2b,2y
   * @param random  the secure random instance to use
   */
  public BCryptPasswordEncoder(BCryptVersion version, SecureRandom random) {
    this(version, -1, random);
  }

  /**
   * @param strength the log rounds to use, between 4 and 31
   * @param random   the secure random instance to use
   */
  public BCryptPasswordEncoder(int strength, SecureRandom random) {
    this(BCryptVersion.$2A, strength, random);
  }

  /**
   * @param version  the version of bcrypt, can be 2a,2b,2y
   * @param strength the log rounds to use, between 4 and 31
   */
  public BCryptPasswordEncoder(BCryptVersion version, int strength) {
    this(version, strength, null);
  }

  /**
   * @param version  the version of bcrypt, can be 2a,2b,2y
   * @param strength the log rounds to use, between 4 and 31
   * @param random   the secure random instance to use
   */
  public BCryptPasswordEncoder(BCryptVersion version, int strength, SecureRandom random) {
    if (strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS || strength > BCrypt.MAX_LOG_ROUNDS)) {
      throw new IllegalArgumentException("Bad strength");
    }
    mVersion = version;
    mStrength = strength == -1 ? 10 : strength;
    mRandom = random;
  }

  public String encode(CharSequence rawPassword) {
    String salt;
    if (mRandom != null) {
      salt = BCrypt.gensalt(mVersion.getVersion(), mStrength, mRandom);
    } else {
      salt = BCrypt.gensalt(mVersion.getVersion(), mStrength);
    }
    return BCrypt.hashpw(rawPassword.toString(), salt);
  }

  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (encodedPassword == null || encodedPassword.length() == 0) {
      LOG.warn("Empty encoded password");
      return false;
    }

    if (!mBcryptPattern.matcher(encodedPassword).matches()) {
      LOG.warn("Encoded password does not look like BCrypt");
      return false;
    }
    return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
  }

  @Override
  public boolean upgradeEncoding(String encodedPassword) {
    if (encodedPassword == null || encodedPassword.length() == 0) {
      LOG.warn("Empty encoded password");
      return false;
    }

    Matcher matcher = mBcryptPattern.matcher(encodedPassword);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Encoded password does not look like BCrypt: "
              + encodedPassword);
    } else {
      int strength = Integer.parseInt(matcher.group(2));
      return strength < this.mStrength;
    }
  }

   /**
    * Stores the default bcrypt version for use in configuration.
    *
    * @author Lin Feng
    */
  public enum BCryptVersion {
    $2A("$2a"),
    $2Y("$2y"),
    $2B("$2b");

    private final String mVersion;

    BCryptVersion(String version) {
      mVersion = version;
    }

    public String getVersion() {
      return this.mVersion;
    }
  }
}
