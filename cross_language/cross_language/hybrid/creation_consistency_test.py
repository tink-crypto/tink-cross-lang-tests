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
from cross_language.hybrid import ecies_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('mac.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def hybrid_private_keys() -> Iterator[test_key.TestKey]:
  for key in ecies_keys.ecies_keys():
    yield key


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_creation(self):
    """Tests: Creation consistency, supported languages, valid keys."""
    for key in hybrid_private_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        with self.subTest(f'{lang}, {key} ({supported})'):
          keyset = key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(
                lang, keyset, tink.hybrid.HybridDecrypt
            )
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(
                  lang, keyset, tink.hybrid.HybridDecrypt
              )

  def test_creation_public_key(self):
    """Tests: Creation consistency, supported languages, valid keys."""
    for key in hybrid_private_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        with self.subTest(f'{lang}, {key} ({supported})'):
          keyset = key.as_serialized_keyset()
          if supported:
            public_keyset = testing_servers.public_keyset(lang, keyset)
            testing_servers.remote_primitive(
                lang, public_keyset, tink.hybrid.HybridEncrypt
            )
          else:
            with self.assertRaises(tink.TinkError):
              public_keyset = testing_servers.public_keyset(lang, keyset)
              testing_servers.remote_primitive(
                  lang, public_keyset, tink.hybrid.HybridEncrypt
              )


if __name__ == '__main__':
  absltest.main()
