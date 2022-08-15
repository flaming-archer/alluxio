#!/usr/bin/env bash
#
# The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
# (the "License"). You may not use this work except in compliance with the License, which is
# available at www.apache.org/licenses/LICENSE-2.0
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied, as more fully set forth in the License.
#
# See the NOTICE file distributed with this work for information regarding copyright ownership.
#

readonly SCRIPT_DIR=$(cd "$( dirname "$0" )"; pwd)
cd "$SCRIPT_DIR"
./generate-tarballs single -ufs-modules ufs-hadoop-2.10,ufs-hadoop-ozone-1.2.1 -mvn-args "-DskipTests,-Dmaven.javadoc.skip" -target alluxio-2.7.1-sdi-016-bin.tar.gz
