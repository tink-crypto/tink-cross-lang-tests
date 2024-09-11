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
from cross_language.hybrid import hpke_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('hybrid.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def hybrid_private_keys() -> Iterator[test_key.TestKey]:
  for key in ecies_keys.ecies_private_keys():
    yield key
  for key in hpke_keys.hpke_private_keys():
    yield key


def hybrid_public_keys() -> Iterator[test_key.TestKey]:
  for key in ecies_keys.ecies_public_keys():
    yield key
  for key in hpke_keys.hpke_public_keys():
    yield key


def is_supported(key: test_key.TestKey, lang: str) -> bool:
  supported = key.supported_in(lang)
  if 'b/315928577' in key.tags() and lang in ['java', 'go']:
    supported = False
  if 'b/235861932' in key.tags() and lang in ['cc', 'go', 'python']:
    supported = False
  if 'b/361841214' in key.tags() and lang in ['go']:
    supported = False
  return supported


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of HybridDecrypt implementations.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_create_hybrid_decrypt(self):
    """Tests: Creation of HybridDecrypt from private key."""
    for key in hybrid_private_keys():
      for lang in tink_config.all_tested_languages():
        if (lang == 'go' or lang == 'java') and 'b/365925769' in key.tags():
          continue
        supported = is_supported(key, lang)
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

  def test_create_hybrid_encrypt_via_private_key(self):
    """Tests: Creation of HybridEncrypt from private key.

    For keys not supported in a language, this must fail either when we get the
    keyset, or when we create the primitive. Note that getting the keyset alone
    can be fine (for example, Tink may allow getting the public keyset with a
    key size which is too short, but not creating the primitive).
    """
    for key in hybrid_private_keys():
      for lang in tink_config.all_tested_languages():
        if (lang == 'go' or lang == 'java') and 'b/365925769' in key.tags():
          continue
        supported = is_supported(key, lang)
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

  def test_create_hybrid_encrypt_via_public_key(self):
    """Tests: Creation of HybridEncrypt from public key."""
    for key in hybrid_public_keys():
      for lang in tink_config.all_tested_languages():
        supported = is_supported(key, lang)
        with self.subTest(f'{lang}, {key} ({supported})'):
          public_keyset = key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(
                lang, public_keyset, tink.hybrid.HybridEncrypt
            )
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(
                  lang, public_keyset, tink.hybrid.HybridEncrypt
              )


if __name__ == '__main__':
  absltest.main()
