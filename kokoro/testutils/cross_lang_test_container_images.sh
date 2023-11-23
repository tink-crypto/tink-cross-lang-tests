#!/bin/bash
# Copyright 2023 Google LLC
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

_image_prefix() {
  local -r artifact_registry_url="us-docker.pkg.dev"
  local -r test_project="tink-test-infrastructure"
  local -r artifact_registry_repo="tink-ci-images"
  echo "${artifact_registry_url}/${test_project}/${artifact_registry_repo}"
}

# Linux container images for cross language tests.
readonly TINK_CROSS_LANG_BASE_IMAGE_NAME="linux-tink-cross-lang-base"
readonly TINK_CROSS_LANG_BASE_IMAGE_HASH="b2f1935ab3ca0e4b82d997aa4c54e8eabb7ec4d0c8a92354ea146f66dd7eec74"
readonly TINK_CROSS_LANG_BASE_IMAGE="$(_image_prefix)/${TINK_CROSS_LANG_BASE_IMAGE_NAME}@sha256:${TINK_CROSS_LANG_BASE_IMAGE_HASH}"

unset -f _image_prefix
