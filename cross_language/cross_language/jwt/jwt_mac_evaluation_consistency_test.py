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
  testing_servers.start('jwt_mac_evaluation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def jwt_mac_keys() -> Iterator[test_key.TestKey]:
  for key in jwt_hmac_keys.jwt_hmac_keys():
    yield key


class EvaluationConsistencyTest(absltest.TestCase):
  """Tests evaluation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_evaluation_consistency(self):
    """Tests that tokens created in lang1 can be decoded in lang2."""

    for key in jwt_mac_keys():
      for lang1 in tink_config.all_tested_languages():
        for lang2 in tink_config.all_tested_languages():
          if key.supported_in(lang1) and key.supported_in(lang2):
            with self.subTest(f'{lang1} -> {lang2}: {key}'):
              keyset = key.as_serialized_keyset()
              jwt_mac1 = testing_servers.remote_primitive(
                  lang1, keyset, tink.jwt.JwtMac
              )
              jwt_mac2 = testing_servers.remote_primitive(
                  lang1, keyset, tink.jwt.JwtMac
              )
              raw_jwt = tink.jwt.new_raw_jwt(
                  issuer='test_issuer',
                  custom_claims={'CustomClaim1': 'claimed'},
                  without_expiration=True,
              )
              signed_token = jwt_mac1.compute_mac_and_encode(raw_jwt)
              validator = tink.jwt.new_validator(
                  expected_issuer='test_issuer',
                  allow_missing_expiration=True
              )
              verified_jwt = jwt_mac2.verify_mac_and_decode(
                  signed_token, validator
              )
              self.assertEqual(
                  verified_jwt.custom_claim('CustomClaim1'), 'claimed'
              )

  def test_b315970600_keys(self):
    """Tests behavior of b/315970600 keys.

    Keys with OutputPrefixType TINK should not have custom kid set. Optimally
    Tink would prevent creation of JwtMac objects from keys which look like
    this. At the moment this doesn't happen. Hence, it is important that at
    least one cannot create tokens with such a key. This test checks this.
    Note that in this case all which really happens is that the error is thrown
    later than optimal.
    """

    for key in jwt_mac_keys():
      for lang in tink_config.all_tested_languages():
        if lang in ['python'] and 'b/315970600' in key.tags():
          with self.subTest(f'{lang}: {key}'):
            keyset = key.as_serialized_keyset()
            jwt_mac = testing_servers.remote_primitive(
                lang, keyset, tink.jwt.JwtMac
            )
            raw_jwt = tink.jwt.new_raw_jwt(
                issuer='test_issuer',
                custom_claims={'CustomClaim1': 'claimed'},
                without_expiration=True,
            )
            with self.assertRaises(tink.TinkError):
              jwt_mac.compute_mac_and_encode(raw_jwt)


if __name__ == '__main__':
  absltest.main()
