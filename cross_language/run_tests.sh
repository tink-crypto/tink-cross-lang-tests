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

# Run the cross language tests.
#
# Usage:
#   run_tests.sh [-k] [-o Bazel output_user_root]
#
# If output_user_root is not specified, the script will use the default.

set -euo pipefail

readonly TESTING_SERVER_DIR="$(dirname "${0}")"

OUTPUT_USER_ROOT=
TEST_TARGETS="..."
RUN_KMS_TESTS="false"

usage() {
  cat <<EOF
Usage:  $0 [-k] [-o output_user_root]
  -k: [Optional] If should run only KMS tests.
  -o: [Optional] Bazel output_user_root.
  -h: Help. Print this usage information.
EOF
  exit 1
}

absolute_path() {
  echo "$(cd "$(dirname "${1}")" && pwd)/$(basename "${1}")"
}

process_args() {
  # Parse options.
  while getopts "hko:" opt; do
    case "${opt}" in
      k) RUN_KMS_TESTS="true" ;;
      o) OUTPUT_USER_ROOT="$(absolute_path "${OPTARG}")" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly RUN_KMS_TESTS
  readonly OUTPUT_USER_ROOT
  if [[ "${RUN_KMS_TESTS}" == "true" ]]; then
    TEST_TARGETS="//cross_language:kms_aead_test"
  fi
  readonly TEST_TARGETS
}

process_args "$@"

BAZEL_STARTUP_OPTS=()
if [[ -n "${OUTPUT_USER_ROOT}" ]]; then
  BAZEL_STARTUP_OPTS+=("--output_user_root=${OUTPUT_USER_ROOT}")
fi
readonly BAZEL_STARTUP_OPTS

TEST_OPTIONS=(
  --test_output=errors
  --test_env=TINK_CROSS_LANG_ROOT_PATH="$(pwd)"
  --experimental_ui_max_stdouterr_bytes=-1
)

# TODO(b/276277854) It is not clear why this is needed.
pip3 install protobuf==4.24.3 --user

if [[ "${RUN_KMS_TESTS}" == "true" ]]; then
  pip3 install google-cloud-kms==2.15.0 --user
  pip3 install hvac==2.1.0 --user

  # Setup a local HashCorp Vault server.
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

  # Pass the vault token to the test.
  TEST_OPTIONS+=( --test_env=VAULT_TOKEN="${VAULT_TOKEN}" )
fi

readonly TEST_OPTIONS

(
  set -x

  cd "${TESTING_SERVER_DIR}"
  # Run tests.
  time bazelisk "${BAZEL_STARTUP_OPTS}" test "${TEST_OPTIONS[@]}" -- \
    "${TEST_TARGETS}"
)
