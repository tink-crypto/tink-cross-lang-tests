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
# tink-cross-lang-tests and its dependencies. That is:
#   ${TINK_BASE_DIR}/tink-cc
#   ${TINK_BASE_DIR}/tink-go
#   ${TINK_BASE_DIR}/tink-java
#   ${TINK_BASE_DIR}/tink-py
# NOTE: They are fetched from GitHub if not found.
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
  "${GITHUB_ORG}/tink-go"
  "${GITHUB_ORG}/tink-java"
  "${GITHUB_ORG}/tink-py"
)
# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${DEPS[@]}"

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_build.sh _do_test.sh
  # Give ownership to the current user.
  sudo chown -R "$(id -un):$(id -gn)" bazel/
}

cat <<'EOF' > _do_build.sh
#!/bin/bash
set -xeuo pipefail
readonly FOLDER="$1"
readonly BUILD_TARGETS=("${@:2}")
readonly OUTPUT_USER_ROOT="$(pwd)/bazel"
cd "${FOLDER}"
time bazelisk --output_user_root="${OUTPUT_USER_ROOT}" build \
  -- "${BUILD_TARGETS[@]}"
EOF
chmod +x _do_build.sh

cat <<'EOF' > _do_test.sh
#!/bin/bash
set -xeuo pipefail
readonly FOLDER="$1"
readonly TEST_TARGETS=("${@:2}")
readonly OUTPUT_USER_ROOT="$(pwd)/bazel"
readonly TINK_CROSS_LANG_ROOT_PATH="$(pwd)"
cd "${FOLDER}"
TEST_OPTIONS=( --test_output=errors )
if [[ "${FOLDER}" == "cross_language" ]]; then
  TEST_OPTIONS+=(
    --test_env=TINK_CROSS_LANG_ROOT_PATH="${TINK_CROSS_LANG_ROOT_PATH}"
    --experimental_ui_max_stdouterr_bytes=-1
  )
  # TODO(b/276277854) It is not clear why this is needed.
  pip3 install protobuf==4.24.3 --user
  pip3 install hvac==2.1.0 --user
fi
readonly TEST_OPTIONS
time bazelisk --output_user_root="${OUTPUT_USER_ROOT}" test \
  "${TEST_OPTIONS[@]}" -- "${TEST_TARGETS[@]}"
EOF
chmod +x _do_test.sh

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

run "${CC_CONTAINER_IMAGE:-}" ./_do_build.sh cc ...
run "${CC_CONTAINER_IMAGE:-}" ./_do_test.sh cc ...
run "${GO_CONTAINER_IMAGE:-}" ./_do_build.sh go ...
run "${GO_CONTAINER_IMAGE:-}" ./_do_test.sh go ...
run "${JAVA_CONTAINER_IMAGE:-}" ./_do_build.sh java_src ... \
  //:testing_server_deploy.jar
run "${JAVA_CONTAINER_IMAGE:-}" ./_do_test.sh java_src ...
run "${PY_CONTAINER_IMAGE:-}" ./_do_build.sh python ...
run "${PY_CONTAINER_IMAGE:-}" ./_do_test.sh python ...
run "${CROSS_LANG_CONTAINER_IMAGE:-}" ./_do_build.sh cross_language ...
run "${CROSS_LANG_CONTAINER_IMAGE:-}" ./_do_test.sh cross_language ...
