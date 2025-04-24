#!/bin/bash
# Copyright 2022 Google LLC
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

# By default when run locally this script executes tests directly on the host.
# The *_CONTAINER_IMAGE variables can be set to execute tests in custom
# container images for local testing. E.g.:
#
# _CONTAINER_IMAGE_BASE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images" /
#   CC_CONTAINER_IMAGE="${_CONTAINER_IMAGE_BASE}/linux-tink-cc-base:latest" /
#   CROSS_LANG_CONTAINER_IMAGE="${CROSS_LANG_CONTAINER_IMAGE}/linux-tink-cross-lang-base:latest" /
#   GO_CONTAINER_IMAGE="${_CONTAINER_IMAGE_BASE}/linux-tink-go-base:latest" /
#   PY_CONTAINER_IMAGE="${_CONTAINER_IMAGE_BASE}/linux-tink-py-base:latest" /
#   JAVA_CONTAINER_IMAGE="${_CONTAINER_IMAGE_BASE}/linux-tink-java-base:latest" /
#   sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh
#
# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-cross-lang-tests and its dependencies, which are fetched from GitHub if
# not found.
set -eEuo pipefail

IS_KOKORO="false"
if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

readonly CROSS_LANG_TESTS_WORKSPACES=(
  "cc"
  "go"
  "java_src"
  "python"
  "cross_language"
)

if [[ "${IS_KOKORO}" == "true" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cross_lang_tests"
  source "./kokoro/testutils/cc_test_container_images.sh"
  source "./kokoro/testutils/cross_lang_test_container_images.sh"
  source "./kokoro/testutils/go_test_container_images.sh"
  source "./kokoro/testutils/java_test_container_images.sh"
  source "./kokoro/testutils/py_test_container_images.sh"
  CC_CONTAINER_IMAGE="${TINK_CC_BASE_IMAGE}"
  CROSS_LANG_CONTAINER_IMAGE="${TINK_CROSS_LANG_BASE_IMAGE}"
  GO_CONTAINER_IMAGE="${TINK_GO_BASE_IMAGE}"
  JAVA_CONTAINER_IMAGE="${TINK_JAVA_BASE_IMAGE}"
  PY_CONTAINER_IMAGE="${TINK_PY_BASE_IMAGE}"
fi
: "${TINK_BASE_DIR:=$(cd .. && pwd)}"
readonly TINK_BASE_DIR
readonly CC_CONTAINER_IMAGE
readonly GO_CONTAINER_IMAGE
readonly JAVA_CONTAINER_IMAGE
readonly PY_CONTAINER_IMAGE
readonly CROSS_LANG_CONTAINER_IMAGE

readonly GITHUB_ORG="https://github.com/tink-crypto"
readonly DEPS=(
  "${GITHUB_ORG}/tink-cc"
  "${GITHUB_ORG}/tink-cc-awskms"
  "${GITHUB_ORG}/tink-cc-gcpkms"
  "${GITHUB_ORG}/tink-go"
  "${GITHUB_ORG}/tink-go-awskms"
  "${GITHUB_ORG}/tink-go-gcpkms"
  "${GITHUB_ORG}/tink-go-hcvault"
  "${GITHUB_ORG}/tink-java"
  "${GITHUB_ORG}/tink-java-awskms"
  "${GITHUB_ORG}/tink-java-gcpkms"
  "${GITHUB_ORG}/tink-java-hcvault"
  "${GITHUB_ORG}/tink-py"
)
# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${DEPS[@]}"

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  # Give ownership of the Bazel root folder to the current user.
  sudo chown -R "$(id -un):$(id -gn)" bazel/
}

run() {
  local -r container_img="${1:-}"
  local -r command=("${@:2}")
  local run_command_args=()
  if [[ "${IS_KOKORO}" == "true" ]] ; then
    run_command_args+=( -k "${TINK_GCR_SERVICE_KEY}" )
  fi
  if [[ -n "${container_img:-}" ]]; then
    run_command_args+=( -c "${container_img}" )
  fi
  readonly run_command_args
  ./kokoro/testutils/run_command.sh "${run_command_args[@]}" "${command[@]}"
}

readonly OUTPUT_USER_ROOT="bazel"

# Build test servers.
if [[ "${IS_KOKORO}" == "true" ]] ; then
  # Make the key available to the build scripts running in the containers.
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" cache_key
fi

echo "== BUILDING C++ SERVER =================================================="
run "${CC_CONTAINER_IMAGE:-}" bash cc/build_server.sh -o "${OUTPUT_USER_ROOT}"
echo "== BUILDING GO SERVER ==================================================="
run "${GO_CONTAINER_IMAGE:-}" bash go/build_server.sh -o "${OUTPUT_USER_ROOT}"
echo "== BUILDING JAVA SERVER ================================================="
run "${JAVA_CONTAINER_IMAGE:-}" bash java_src/build_server.sh \
  -o "${OUTPUT_USER_ROOT}"
echo "== BUILDING PYTHON SERVER ==============================================="
run "${PY_CONTAINER_IMAGE:-}" bash python/build_server.sh \
  -o "${OUTPUT_USER_ROOT}"

echo "== RUNNING CROSS LANGUAGE TESTS ========================================="
run "${CROSS_LANG_CONTAINER_IMAGE:-}" bash cross_language/run_tests.sh \
  -o "${OUTPUT_USER_ROOT}"
