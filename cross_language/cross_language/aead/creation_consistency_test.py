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
from cross_language.aead import aes_ctr_hmac_aead_keys
from cross_language.aead import aes_eax_keys
from cross_language.aead import aes_gcm_keys
from cross_language.aead import aes_gcm_siv_keys
from cross_language.aead import chacha20_poly1305_keys
from cross_language.aead import x_aes_gcm_keys
from cross_language.aead import xchacha20_poly1305_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.aead.register()
  testing_servers.start('aead.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def aead_keys() -> Iterator[test_key.TestKey]:
  for key in aes_ctr_hmac_aead_keys.aes_ctr_hmac_aead_keys():
    yield key
  for key in aes_eax_keys.aes_eax_keys():
    yield key
  for key in aes_gcm_keys.aes_gcm_keys():
    yield key
  for key in aes_gcm_siv_keys.aes_gcm_siv_keys():
    yield key
  for key in chacha20_poly1305_keys.chacha20_poly1305_keys():
    yield key
  for key in xchacha20_poly1305_keys.xchacha20_poly1305_keys():
    yield key
  for key in x_aes_gcm_keys.x_aes_gcm_keys():
    yield key


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of aead implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_creation(self):
    """Tests: Creation consistency, supported languages, valid keys."""
    for key in aead_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        supported_string = '(should work)' if supported else '(should fail)'
        with self.subTest(f'{lang}, {key} {supported_string}'):
          keyset = key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(lang, keyset, tink.aead.Aead)
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(lang, keyset, tink.aead.Aead)


if __name__ == '__main__':
  absltest.main()
