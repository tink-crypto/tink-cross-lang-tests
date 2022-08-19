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

CURRENT_BAZEL_VERSION=
TINK_CROSS_LANG_ROOT_PATH=

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

build_all() {
  local -r folder="$1"
  shift 1
  local -r extra_build_targets=("$@")

  cp "${folder}/WORKSPACE" "${folder}/WORKSPACE.bak"
  ./kokoro/testutils/replace_http_archive_with_local_repository.py \
    -f "${folder}/WORKSPACE" -t "${TINK_BASE_DIR}"
  (
    cd "${folder}"
    use_bazel "$(cat .bazelversion)"
    local targets=( "..." )
    if (( "${#extra_build_targets[@]}" > 0 )); then
      targets+=( "${extra_build_targets[@]}" )
    fi
    time bazel build -- "${targets[@]}"
  )
}

run_tests() {
  local -r folder="$1"
  shift 1
  local -r test_targets=("$@")
  local test_options=( --test_output=errors )
  if [[ -n "${TINK_CROSS_LANG_ROOT_PATH}" ]]; then
    test_options+=(
      --test_env TINK_CROSS_LANG_ROOT_PATH="${TINK_CROSS_LANG_ROOT_PATH}"
    )
  fi
  readonly test_options
  (
    cd "${folder}"
    time bazel test "${test_options[@]}" -- "${test_targets[@]}"
  )
}

main() {
  if [[ -n "${KOKORO_ROOT:-}" ]] ; then
    cd "${KOKORO_ARTIFACTS_DIR}/git/tink_cross_lang_tests"
    ./kokoro/testutils/update_android_sdk.sh
    # Sourcing required to update callers environment.
    source ./kokoro/testutils/install_python3.sh
    source ./kokoro/testutils/install_go.sh
  fi

  : "${TINK_BASE_DIR:=$(cd .. && pwd)}"

  # Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
  # downloaded.
  readonly GITHUB_ORG="https://github.com/tink-crypto"
  ./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
    "${GITHUB_ORG}/tink-cc" "${GITHUB_ORG}/tink-cc-awskms" \
    "${GITHUB_ORG}/tink-cc-gcpkms" "${GITHUB_ORG}/tink-go" \
    "${GITHUB_ORG}/tink-java" "${GITHUB_ORG}/tink-py"

  set -x

  ./kokoro/testutils/copy_credentials.sh "cc/testdata" "gcp"
  ./kokoro/testutils/copy_credentials.sh "cross_language/testdata" "gcp"

  build_all cc
  run_tests cc "..."
  build_all go
  run_tests go "..."
  build_all java_src ":testing_server_deploy.jar"
  run_tests java_src "..."
  build_all python
  run_tests python "..."
  build_all cross_language
  TINK_CROSS_LANG_ROOT_PATH="${PWD}"
  run_tests cross_language "//:kms_envelope_aead_test"
}

main "$@"
