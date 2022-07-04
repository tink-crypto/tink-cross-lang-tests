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

# The user may specify TINK_BASE_DIR for setting the base folder where the
# script should look for the dependencies of this project.

set -euo pipefail

CURRENT_BAZEL_VERSION=""

use_bazel() {
  local candidate_version="$1"
  if [[ "${candidate_version}" != "${CURRENT_BAZEL_VERSION}" ]]; then
    CURRENT_BAZEL_VERSION="${candidate_version}"
    if [[ -n "${KOKORO_ROOT:-}" ]] ; then
      use_bazel.sh "${candidate_version}"
    else
      bazel --version
    fi
  fi
}

build_and_run_tests() {
  local folder="$1"
  local extra_build_target="${2:-}"
  local tink_cross_lang_root_path="${3:-}"
  cp "${folder}/WORKSPACE" "${folder}/WORKSPACE.bak"
  ./kokoro/testutils/replace_http_archive_with_local_repository.py \
    -f "${folder}/WORKSPACE" \
    -t "${TINK_BASE_DIR}"
  (
    cd "${folder}"
    use_bazel "$(cat .bazelversion)"
    time bazel build -- ...
    if [[ -n "${extra_build_target}" ]]; then
      time bazel build "${extra_build_target}"
    fi
    local test_options=( --test_output=errors )
    if [[ -n "${tink_cross_lang_root_path}" ]]; then
      test_options+=(
        --test_env TINK_CROSS_LANG_ROOT_PATH="${tink_cross_lang_root_path}"
      )
    fi
    time bazel test "${test_options[@]}" -- ...
  )
  cp "${folder}/WORKSPACE.bak" "${folder}/WORKSPACE"
}

main() {
  if [[ -n "${KOKORO_ROOT:-}" ]] ; then
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink_cross_lang_tests"
    ./kokoro/testutils/update_android_sdk.sh
    # Sourcing required to update callers environment.
    source ./kokoro/testutils/install_python3.sh
    source ./kokoro/testutils/install_go.sh
  fi

  # Note: When running on the Kokoro CI, we expect these folders to exist:
  #
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_cc
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_cc_awskms
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_cc_gcpkms
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_go
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_java
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_py
  #  ${KOKORO_ARTIFACTS_DIR}/git/tink_cross_lang_tests
  #
  # If this is not the case, we are using this script locally for a manual
  # one-off test running it from the root of a local copy of the repo under
  # test.
  : "${TINK_BASE_DIR:=$(pwd)/..}"

  local dependencies=(
    "tink-cc"
    "tink-cc-awskms"
    "tink-cc-gcpkms"
    "tink-go"
    "tink-java"
    "tink-py"
  )

  # If dependencies aren't in TINK_BASE_DIR we fetch them from GitHub.
  for dependency in "${dependencies[@]}"; do
    folder="$(echo ${dependency} | sed 's#-#_#g')"
    if [[ ! -d "${TINK_BASE_DIR}/${folder}" ]]; then
      git clone "https://github.com/tink-crypto/${dependency}.git" \
        "${TINK_BASE_DIR}/${folder}"
    fi
  done

  build_and_run_tests cc
  build_and_run_tests go
  build_and_run_tests java_src :testing_server_deploy.jar
  build_and_run_tests python
  build_and_run_tests cross_language "" "${PWD}"
}

main "$@"
