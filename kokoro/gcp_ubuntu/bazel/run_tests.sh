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

BAZEL_CMD="bazel"
CURRENT_BAZEL_VERSION=""

build_and_run_tests() {
  local folder="$1"
  local extra_build_target="${2:-}"
  local tink_cross_lang_root_path="${3:-}"
  cp "${folder}/WORKSPACE" "${folder}/WORKSPACE.bak"
  ./kokoro/testutils/replace_http_archive_with_local_repository.py \
    -f "${folder}/WORKSPACE" -t "${TINK_BASE_DIR}"
  (
    cd "${folder}"
    "${BAZEL_CMD}" --version
    time "${BAZEL_CMD}" build -- ...
    if [[ -n "${extra_build_target}" ]]; then
      time "${BAZEL_CMD}" build "${extra_build_target}"
    fi
    local test_options=( --test_output=errors )
    if [[ -n "${tink_cross_lang_root_path}" ]]; then
      test_options+=(
        --test_env TINK_CROSS_LANG_ROOT_PATH="${tink_cross_lang_root_path}"
      )
    fi
    time "${BAZEL_CMD}" test "${test_options[@]}" -- ...
  )
  cp "${folder}/WORKSPACE.bak" "${folder}/WORKSPACE"
}

main() {
  if [[ -n "${KOKORO_ROOT:-}" ]] ; then
    TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
    cd "${TINK_BASE_DIR}/tink_cross_lang_tests"
    if command -v "bazelisk" &> /dev/null; then
      BAZEL_CMD="bazelisk"
    fi
  fi
  readonly BAZEL_CMD

  : "${TINK_BASE_DIR:=$(cd .. && pwd)}"
  readonly TINK_BASE_DIR

  # Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
  # downloaded.
  readonly GITHUB_ORG="https://github.com/tink-crypto"
  ./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
    "${GITHUB_ORG}/tink-cc" "${GITHUB_ORG}/tink-cc-awskms" \
    "${GITHUB_ORG}/tink-cc-gcpkms" "${GITHUB_ORG}/tink-go" \
    "${GITHUB_ORG}/tink-java" "${GITHUB_ORG}/tink-py"

  build_and_run_tests cc
  build_and_run_tests go
  build_and_run_tests java_src :testing_server_deploy.jar
  build_and_run_tests python
  build_and_run_tests cross_language "" "${PWD}"
}

main "$@"
