#!/bin/bash
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# Simple script to build the testing server.

set -euo pipefail

readonly GCS_URL="https://storage.googleapis.com"
readonly TESTING_SERVER_DIR="$(dirname "${0}")"
readonly BAZEL_CACHE_URL="${GCS_URL}/tink-ci-remote-cache/bazel/cross-lang-tests"
readonly BAZEL_CACHE_KEY_FILE="$(realpath ./cache_key)"
OUTPUT_USER_ROOT=

usage() {
  cat <<EOF
Usage:  $0 [-o output_user_root]
  -o: [Optional] Bazel output_user_root.
  -h: Help. Print this usage information.
EOF
  exit 1
}

process_args() {
  # Parse options.
  while getopts "ho:" opt; do
    case "${opt}" in
      o) OUTPUT_USER_ROOT="$(realpath "${OPTARG}")" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly OUTPUT_USER_ROOT
}

process_args "$@"

BAZEL_STARTUP_OPTS=()
if [[ -n "${OUTPUT_USER_ROOT}" ]]; then
  BAZEL_STARTUP_OPTS+=("--output_user_root=${OUTPUT_USER_ROOT}")
fi
readonly BAZEL_STARTUP_OPTS

CACHE_OPTS=()
if [[ -f "${BAZEL_CACHE_KEY_FILE}" ]]; then
  CACHE_OPTS+=(
    "--remote_cache=${BAZEL_CACHE_URL}"
    "--google_credentials=${BAZEL_CACHE_KEY_FILE}"
  )
fi
readonly CACHE_OPTS

readonly TEST_OPTIONS=( --test_output=errors )

(
  set -x
  export ANDROID_HOME=/android-sdk-30
  cd "${TESTING_SERVER_DIR}"
  time bazelisk "${BAZEL_STARTUP_OPTS[@]}" build "${CACHE_OPTS[@]}" -- ... \
    //:testing_server_deploy.jar
  time bazelisk "${BAZEL_STARTUP_OPTS[@]}" test "${CACHE_OPTS[@]}" \
    "${TEST_OPTIONS[@]}" -- ...
)
