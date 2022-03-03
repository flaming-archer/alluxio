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

public class Timer {

  /**
   * Current system time.  Do not use this to calculate a duration or interval
   * to sleep, because it will be broken by settimeofday.  Instead, use
   * monotonicNow.
   * @return current time in msec
   */
  public long now() {
    return Time.now();
  }

  /**
   * Current time from some arbitrary time base in the past, counting in
   * milliseconds, and not affected by settimeofday or similar system clock
   * changes.  This is appropriate to use when computing how much longer to
   * wait for an interval to expire.
   * @return a monotonic clock that counts in milliseconds
   */
  public long monotonicNow() {
    return Time.monotonicNow();
  }
}
