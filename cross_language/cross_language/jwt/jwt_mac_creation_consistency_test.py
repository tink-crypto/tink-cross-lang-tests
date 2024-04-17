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

from typing import Iterator

from absl.testing import absltest
import tink

from cross_language import test_key
from cross_language import tink_config
from cross_language.jwt import jwt_hmac_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('mac.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def jwt_mac_keys() -> Iterator[test_key.TestKey]:
  for key in jwt_hmac_keys.jwt_hmac_keys():
    yield key


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_creation(self):
    """Tests: Creation consistency, supported languages, valid keys."""
    for key in jwt_mac_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        if lang in ['go', 'python'] and 'b/315970600' in key.tags():
          supported = True
        supported_string = 'should work' if supported else 'should throw'
        with self.subTest(f'{lang}, {key}, {supported_string}'):
          keyset = key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(lang, keyset, tink.jwt.JwtMac)
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(lang, keyset, tink.jwt.JwtMac)

if __name__ == '__main__':
  absltest.main()
