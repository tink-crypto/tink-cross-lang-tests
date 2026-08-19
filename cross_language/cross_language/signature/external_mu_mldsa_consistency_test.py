# Copyright 2026 Google LLC
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

"""Cross-language test for External Mu ML-DSA 3-way consistency.

Tests: create prehash in one language (lang1), sign in another (lang2), and
verify in a third language (lang3).
"""

import os
import random

from absl.testing import absltest
import tink

from cross_language.signature import mldsa_keys
from cross_language.util import _primitives
from cross_language.util import testing_servers


def setUpModule():
  testing_servers.start('signature.external_mu_mldsa_consistency_test')


def tearDownModule():
  testing_servers.stop()


# Languages that support External Mu ML-DSA (Prehash and SignPrehash).
SUPPORTED_LANGUAGES = ['cc', 'go']
UNSUPPORTED_LANGUAGES = ['java', 'python']


class ExternalMuMlDsaConsistencyTest(absltest.TestCase):
  """Tests 3-way consistency for External Mu ML-DSA.

  Computes prehash in lang1, signs prehash in lang2, and verifies signature in
  lang3.
  """

  def test_3way_external_mu_mldsa_consistency(self):
    for key in mldsa_keys.external_mu_mldsa_private_keys():
      for lang1 in SUPPORTED_LANGUAGES:
        for lang2 in SUPPORTED_LANGUAGES:
          for lang3 in SUPPORTED_LANGUAGES:
            with self.subTest(f'{lang1}->{lang2}->{lang3}: {key}'):
              private_keyset = key.as_serialized_keyset()
              public_keyset = testing_servers.public_keyset(
                  lang1, private_keyset
              )
              prehasher = testing_servers.remote_primitive(
                  lang1, public_keyset, _primitives.Prehash
              )
              signer = testing_servers.remote_primitive(
                  lang2, private_keyset, _primitives.PrehashSigner
              )
              verifier = testing_servers.remote_primitive(
                  lang3, public_keyset, tink.signature.PublicKeyVerify
              )
              message = os.urandom(random.choice([0, 1, 17, 31, 1027]))
              prehash = prehasher.compute_prehash(message)
              signature = signer.sign_prehash(prehash)
              verifier.verify(signature, message)

  def test_unsupported_languages_fail(self):
    for key in mldsa_keys.external_mu_mldsa_private_keys():
      private_keyset = key.as_serialized_keyset()
      public_keyset = testing_servers.public_keyset('cc', private_keyset)
      for lang in UNSUPPORTED_LANGUAGES:
        with self.subTest(f'Prehash in {lang}'):
          with self.assertRaises(tink.TinkError):
            testing_servers.remote_primitive(
                lang, public_keyset, _primitives.Prehash
            )
        with self.subTest(f'PrehashSigner in {lang}'):
          with self.assertRaises(tink.TinkError):
            testing_servers.remote_primitive(
                lang, private_keyset, _primitives.PrehashSigner
            )


if __name__ == '__main__':
  absltest.main()
