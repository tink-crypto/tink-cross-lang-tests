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
from cross_language.jwt import jwt_ecdsa_keys
from cross_language.util import testing_servers


def setUpModule():
  testing_servers.start('jwt_signature.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def signature_private_keys() -> Iterator[test_key.TestKey]:
  for key in jwt_ecdsa_keys.jwt_ecdsa_private_keys():
    yield key


def signature_public_keys() -> Iterator[test_key.TestKey]:
  for key in jwt_ecdsa_keys.jwt_ecdsa_public_keys():
    yield key


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_create_jwt_public_key_sign(self):
    """Tests: Creation of JwtPublicKeySign from private key."""
    for key in signature_private_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        if lang == 'go' and 'b/316869725' in key.tags():
          supported = True
        with self.subTest(f'{lang}, {key} ({supported})'):
          keyset = key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(
                lang, keyset, tink.jwt.JwtPublicKeySign
            )
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(
                  lang, keyset, tink.jwt.JwtPublicKeySign
              )

  def test_create_jwt_public_key_verify_via_private_key(self):
    """Tests: Creation of JwtPublicKeyVerify from private key.

    For keys not supported in a language, this must fail either when we get the
    keyset, or when we create the primitive. Note that getting the keyset alone
    can be fine (for example, Tink may allow getting the public keyset with a
    key size which is too short, but not creating the primitive).
    """
    for key in signature_private_keys():
      for lang in tink_config.all_tested_languages():
        supported = key.supported_in(lang)
        with self.subTest(f'{lang}, {key} ({supported})'):
          keyset = key.as_serialized_keyset()
          if supported:
            public_keyset = testing_servers.public_keyset(lang, keyset)
            testing_servers.remote_primitive(
                lang, public_keyset, tink.jwt.JwtPublicKeyVerify
            )
          else:
            with self.assertRaises(tink.TinkError):
              public_keyset = testing_servers.public_keyset(lang, keyset)
              testing_servers.remote_primitive(
                  lang, public_keyset, tink.jwt.JwtPublicKeyVerify
              )

  def test_create_jwt_public_key_verify_via_public_key(self):
    """Tests: Creation of JwtPublicKeyVerify from public key."""
    for public_key in signature_public_keys():
      for lang in tink_config.all_tested_languages():
        supported = public_key.supported_in(lang)
        with self.subTest(f'{lang}, {public_key} ({supported})'):
          public_keyset = public_key.as_serialized_keyset()
          if supported:
            testing_servers.remote_primitive(
                lang, public_keyset, tink.jwt.JwtPublicKeyVerify
            )
          else:
            with self.assertRaises(tink.TinkError):
              testing_servers.remote_primitive(
                  lang, public_keyset, tink.jwt.JwtPublicKeyVerify
              )


if __name__ == '__main__':
  absltest.main()
