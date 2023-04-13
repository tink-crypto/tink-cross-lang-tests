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
BAZEL_CMD="bazel"

build_all() {
  local -r folder="$1"
  shift 1
  local -r extra_build_targets=("$@")

  cp "${folder}/WORKSPACE" "${folder}/WORKSPACE.bak"
  ./kokoro/testutils/replace_http_archive_with_local_repository.py \
    -f "${folder}/WORKSPACE" -t "${TINK_BASE_DIR}"
  (
    cd "${folder}"
    "${BAZEL_CMD}" --version
    local targets=( "..." )
    if (( "${#extra_build_targets[@]}" > 0 )); then
      targets+=( "${extra_build_targets[@]}" )
    fi
    time "${BAZEL_CMD}" build -- "${targets[@]}"
  )
}

run_tests() {
  local -r folder="$1"
  shift 1
  local -r test_targets=("$@")
  local test_options=()
  if [[ -n "${TINK_CROSS_LANG_ROOT_PATH}" ]]; then
    test_options+=(
      --test_output=all
      --test_env TINK_CROSS_LANG_ROOT_PATH="${TINK_CROSS_LANG_ROOT_PATH}"
    )
  else
    test_options+=( --test_output=errors )
  fi
  readonly test_options
  (
    cd "${folder}"
    time "${BAZEL_CMD}" test "${test_options[@]}" -- "${test_targets[@]}"
  )
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

  # TODO(b/276277854) It is not clear why this is needed.
  pip3 install protobuf==4.21.9 --user
  pip3 install google-cloud-kms==2.15.0 --user

  # Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
  # downloaded.
  readonly GITHUB_ORG="https://github.com/tink-crypto"
  ./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
    "${GITHUB_ORG}/tink-cc" "${GITHUB_ORG}/tink-cc-awskms" \
    "${GITHUB_ORG}/tink-cc-gcpkms" "${GITHUB_ORG}/tink-go" \
    "${GITHUB_ORG}/tink-java" "${GITHUB_ORG}/tink-py"

  set -x

  ./kokoro/testutils/copy_credentials.sh "cross_language/testdata" "all"

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
  run_tests cross_language "//:kms_aead_test"
}

main "$@"
