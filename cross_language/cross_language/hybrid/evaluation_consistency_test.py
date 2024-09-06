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
from cross_language.hybrid import ecies_keys
from cross_language.hybrid import hpke_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.hybrid.register()
  testing_servers.start('hybrid.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def hybrid_keys() -> Iterator[test_key.TestKey]:
  for key in ecies_keys.ecies_private_keys():
    yield key
  for key in hpke_keys.hpke_private_keys():
    yield key


class EvaluationConsistencyTest(absltest.TestCase):
  """Tests evaluation consistency of HybridEncrypt/Decrypt implementations.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_evaluation_consistency(self):
    for key in hybrid_keys():
      for lang1 in tink_config.all_tested_languages():
        for lang2 in tink_config.all_tested_languages():
          langs = {lang1, lang2}
          both_lang_supported = all(key.supported_in(lang) for lang in langs)
          if 'b/315928577' in key.tags() and {'java', 'go'} & langs:
            both_lang_supported = False
          if 'b/235861932' in key.tags() and {'python', 'cc', 'go'} & langs:
            both_lang_supported = False
          if 'b/361841214' in key.tags() and {'go'} & langs:
            both_lang_supported = False

          if both_lang_supported:
            with self.subTest(f'{lang1}->{lang2}: {key}'):
              keyset = key.as_serialized_keyset()
              hybrid_decrypt = testing_servers.remote_primitive(
                  lang2, keyset, tink.hybrid.HybridDecrypt
              )
              public_keyset = testing_servers.public_keyset(lang1, keyset)
              hybrid_encrypt = testing_servers.remote_primitive(
                  lang1, public_keyset, tink.hybrid.HybridEncrypt
              )
              message = os.urandom(random.choice([0, 1, 17, 31, 1027]))
              context_info = os.urandom(random.choice([0, 1, 17, 31, 1027]))
              ciphertext = hybrid_encrypt.encrypt(message, context_info)
              decrypted = hybrid_decrypt.decrypt(ciphertext, context_info)
              self.assertEqual(decrypted, message)


if __name__ == '__main__':
  absltest.main()
