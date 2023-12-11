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

import os
import random
from typing import Iterator

from absl.testing import absltest
import tink

from cross_language import test_key
from cross_language import tink_config
from cross_language.mac import aes_cmac_keys
from cross_language.mac import hmac_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('mac.evaluation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def mac_keys() -> Iterator[test_key.TestKey]:
  for key in hmac_keys.hmac_keys():
    yield key
  for key in aes_cmac_keys.aes_cmac_keys():
    yield key


class EvaluationConsistencyTest(absltest.TestCase):
  """Tests evaluation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_evaluation_consistency(self):
    for key in mac_keys():
      for lang1 in tink_config.all_tested_languages():
        for lang2 in tink_config.all_tested_languages():
          if key.supported_in(lang1) and key.supported_in(lang2):
            with self.subTest(f'{lang1} -> {lang2}: {key}'):
              keyset = key.as_serialized_keyset()
              mac1 = testing_servers.remote_primitive(
                  lang1, keyset, tink.mac.Mac
              )
              mac2 = testing_servers.remote_primitive(
                  lang2, keyset, tink.mac.Mac
              )
              message = os.urandom(random.choice([0, 1, 17, 31, 1027]))
              mac2.verify_mac(mac1.compute_mac(message), message)


if __name__ == '__main__':
  absltest.main()
