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
#   sh ./kokoro/gcp_ubuntu/bazel_kms/run_tests.sh
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

./kokoro/testutils/copy_credentials.sh "cross_language/testdata" "all"

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _bazel_build.sh _bazel_test.sh _go_build_and_test.sh \
    _run_cross_language_test.sh
  # Give ownership to the current user.
  sudo chown -R "$(id -un):$(id -gn)" bazel/
}

cat <<'EOF' > _bazel_build.sh
#!/bin/bash
set -xeEuo pipefail
readonly FOLDER="$1"
readonly BUILD_TARGETS=("${@:2}")
readonly OUTPUT_USER_ROOT="$(pwd)/bazel"
cd "${FOLDER}"
time bazelisk --output_user_root="${OUTPUT_USER_ROOT}" build \
  -- "${BUILD_TARGETS[@]}"
EOF
chmod +x _bazel_build.sh

cat <<'EOF' > _bazel_test.sh
#!/bin/bash
set -xeEuo pipefail
readonly FOLDER="$1"
readonly TEST_TARGETS=("${@:2}")
readonly OUTPUT_USER_ROOT="$(pwd)/bazel"
readonly TINK_CROSS_LANG_ROOT_PATH="$(pwd)"
cd "${FOLDER}"
TEST_OPTIONS=( --test_output=errors )
readonly TEST_OPTIONS
time bazelisk --output_user_root="${OUTPUT_USER_ROOT}" test \
"${TEST_OPTIONS[@]}" -- "${TEST_TARGETS[@]}"
EOF
chmod +x _bazel_test.sh

cat <<'EOF' > _run_cross_language_test.sh
#!/bin/bash
set -xeEuo pipefail
readonly OUTPUT_USER_ROOT="$(pwd)/bazel"
readonly TINK_CROSS_LANG_ROOT_PATH="$(pwd)"
cd cross_language
# TODO(b/276277854) It is not clear why this is needed.
pip3 install protobuf==4.24.3 --user
pip3 install google-cloud-kms==2.15.0 --user
pip3 install hvac==2.1.0 --user

mkdir /tmp/vault-tls

# The following code starts a local hashicorp vault server in dev mode in background.
# see:
# https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-dev-server
# https://developer.hashicorp.com/vault/docs/commands
export VAULT_API_ADDR='https://127.0.0.1:8200'
vault server -dev -dev-tls -dev-tls-cert-dir=/tmp/vault-tls &
sleep 30

export VAULT_TOKEN=`cat ~/.vault-token`
export VAULT_SKIP_VERIFY=true
export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_CACERT='/tmp/vault-tls/vault-ca.pem'

# enable the transit secrets engine and add testkey and derived_testkey, see:
# https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service/eaas-transit
vault secrets enable transit
vault write -f transit/keys/testkey
vault write -f transit/keys/derived_testkey derived=true

echo "HC vault server started and 'testkey' and 'derived_testkey' added."

TEST_OPTIONS+=(
  --test_output=errors
  --test_env=TINK_CROSS_LANG_ROOT_PATH="${TINK_CROSS_LANG_ROOT_PATH}"
  --test_env=VAULT_TOKEN="${VAULT_TOKEN}"
  --experimental_ui_max_stdouterr_bytes=-1
)
readonly TEST_OPTIONS
time bazelisk --output_user_root="${OUTPUT_USER_ROOT}" test \
  "${TEST_OPTIONS[@]}" -- //cross_language:kms_aead_test
EOF
chmod +x _run_cross_language_test.sh

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

run "${CC_CONTAINER_IMAGE:-}" ./_bazel_build.sh cc ...
run "${CC_CONTAINER_IMAGE:-}" ./_bazel_test.sh cc ...

run "${GO_CONTAINER_IMAGE:-}" bash go/build_server.sh

run "${JAVA_CONTAINER_IMAGE:-}" ./_bazel_build.sh java_src ... \
  //:testing_server_deploy.jar
run "${JAVA_CONTAINER_IMAGE:-}" ./_bazel_test.sh java_src ...

run "${PY_CONTAINER_IMAGE:-}" ./_bazel_build.sh python ...
run "${PY_CONTAINER_IMAGE:-}" ./_bazel_test.sh python ...

run "${CROSS_LANG_CONTAINER_IMAGE:-}" ./_bazel_build.sh cross_language ...
run "${CROSS_LANG_CONTAINER_IMAGE:-}" ./_run_cross_language_test.sh
