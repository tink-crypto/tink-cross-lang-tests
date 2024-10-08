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
from cross_language.signature import ecdsa_keys
from cross_language.signature import ed25519_keys
from cross_language.signature import rsa_ssa_pkcs1_keys
from cross_language.signature import rsa_ssa_pss_keys
from cross_language.util import testing_servers


def setUpModule():
  testing_servers.start('signature.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def signature_private_keys() -> Iterator[test_key.TestKey]:
  for key in ed25519_keys.ed25519_private_keys():
    yield key
  for key in ecdsa_keys.ecdsa_private_keys():
    yield key
  for key in rsa_ssa_pss_keys.rsa_ssa_pss_private_keys():
    yield key
  for key in rsa_ssa_pkcs1_keys.rsa_ssa_pkcs1_private_keys():
    yield key


def signature_public_keys() -> Iterator[test_key.TestKey]:
  for key in ed25519_keys.ed25519_public_keys():
    yield key
  for key in ecdsa_keys.ecdsa_public_keys():
    yield key
  for key in rsa_ssa_pss_keys.rsa_ssa_pss_public_keys():
    yield key
  for key in rsa_ssa_pkcs1_keys.rsa_ssa_pkcs1_public_keys():
    yield key


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_create_public_key_sign(self):
    """Tests: Creation of PublicKeySign from private key."""
    for key in signature_private_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        if 'b/315954817' in key.tags():
          if lang in ['python']:
            supported = True
        with self.subTest(f'{lang}, {key} ({supported})'):
          keyset = key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(
                lang, keyset, tink.signature.PublicKeySign
            )
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(
                  lang, keyset, tink.signature.PublicKeySign
              )

  def test_create_public_key_verify_via_private_key(self):
    """Tests: Creation of PublicKeyVerify from private key.

    For keys not supported in a language, this must fail either when we get the
    keyset, or when we create the primitive. Note that getting the keyset alone
    can be fine (for example, Tink may allow getting the public keyset with a
    key size which is too short, but not creating the primitive).
    """
    for key in signature_private_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        if 'b/315954817' in key.tags():
          if lang in ['python']:
            supported = True
        with self.subTest(f'{lang}, {key} ({supported})'):
          keyset = key.as_serialized_keyset()
          if supported:
            public_keyset = testing_servers.public_keyset(lang, keyset)
            testing_servers.remote_primitive(
                lang, public_keyset, tink.signature.PublicKeyVerify
            )
          else:
            with self.assertRaises(tink.TinkError):
              public_keyset = testing_servers.public_keyset(lang, keyset)
              testing_servers.remote_primitive(
                  lang, public_keyset, tink.signature.PublicKeyVerify
              )

  def test_create_public_key_verify_via_public_key(self):
    """Tests: Creation of PublicKeyVerify from public key."""
    for public_key in signature_public_keys():
      for lang in tink_config.all_tested_languages():
        supported = public_key.supported_in(lang)
        with self.subTest(f'{lang}, {public_key} ({supported})'):
          public_keyset = public_key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(
                lang, public_keyset, tink.signature.PublicKeyVerify
            )
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(
                  lang, public_keyset, tink.signature.PublicKeyVerify
              )


if __name__ == '__main__':
  absltest.main()
