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

import binascii
import os
import random
from typing import Iterator

from absl.testing import absltest
import tink

from cross_language import test_key
from cross_language import tink_config
from cross_language.prf import aes_cmac_prf_keys
from cross_language.prf import hmac_prf_keys
from cross_language.util import testing_servers


def setUpModule():
  testing_servers.start('prf.evaluation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def prf_keys() -> Iterator[test_key.TestKey]:
  for pair in hmac_prf_keys.hmac_prf_keys():
    yield pair
  for pair in aes_cmac_prf_keys.aes_cmac_prf_keys():
    yield pair


class EvaluationConsistencyTest(absltest.TestCase):
  """Tests evaluation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_evaluation_consistency(self):
    for key in prf_keys():
      with self.subTest(f'Testing key {key}'):
        message = os.urandom(random.choice([0, 1, 17, 31, 1027]))
        prf_outputs = {}
        for lang in tink_config.all_tested_languages():
          if key.supported_in(lang):
            prf = testing_servers.remote_primitive(
                lang, key.as_serialized_keyset(), tink.prf.PrfSet
            )
            if 'b/315441300' in key.tags() and lang in ['cc', 'python']:
              with self.assertRaises(tink.TinkError):
                prf.primary().compute(message, 16)
              continue
            prf_outputs[lang] = binascii.hexlify(
                prf.primary().compute(message, 16)
            )
        output_set = set(prf_outputs.values())
        self.assertLessEqual(
            len(output_set), 1, f'PRF Values differ (got {prf_outputs})'
        )


if __name__ == '__main__':
  absltest.main()
