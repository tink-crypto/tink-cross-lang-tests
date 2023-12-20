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
from cross_language.jwt import jwt_rsa_ssa_pkcs1_keys
from cross_language.jwt import jwt_rsa_ssa_pss_keys
from cross_language.util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('jwt_mac_evaluation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def signature_private_keys() -> Iterator[test_key.TestKey]:
  for key in jwt_ecdsa_keys.jwt_ecdsa_private_keys():
    yield key
  for key in jwt_rsa_ssa_pkcs1_keys.jwt_rsa_ssa_pkcs1_private_keys():
    yield key
  for key in jwt_rsa_ssa_pss_keys.jwt_rsa_ssa_pss_private_keys():
    yield key


class EvaluationConsistencyTest(absltest.TestCase):
  """Tests evaluation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_evaluation_consistency(self):
    """Tests that tokens created in lang1 can be decoded in lang2."""

    for key in signature_private_keys():
      for lang1 in tink_config.all_tested_languages():
        for lang2 in tink_config.all_tested_languages():
          if key.supported_in(lang1) and key.supported_in(lang2):
            with self.subTest(f'{lang1} -> {lang2}: {key}'):
              keyset = key.as_serialized_keyset()
              jwt_public_key_sign = testing_servers.remote_primitive(
                  lang1, keyset, tink.jwt.JwtPublicKeySign
              )
              public_keyset = testing_servers.public_keyset(lang2, keyset)
              jwt_public_key_verify = testing_servers.remote_primitive(
                  lang2, public_keyset, tink.jwt.JwtPublicKeyVerify
              )
              raw_jwt = tink.jwt.new_raw_jwt(
                  issuer='test_issuer',
                  custom_claims={'CustomClaim1': 'claimed'},
                  without_expiration=True,
              )
              signed_token = jwt_public_key_sign.sign_and_encode(raw_jwt)
              validator = tink.jwt.new_validator(
                  expected_issuer='test_issuer',
                  allow_missing_expiration=True
              )
              verified_jwt = jwt_public_key_verify.verify_and_decode(
                  signed_token, validator
              )
              self.assertEqual(
                  verified_jwt.custom_claim('CustomClaim1'), 'claimed'
              )


if __name__ == '__main__':
  absltest.main()
