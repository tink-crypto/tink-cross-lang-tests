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
verify in a third language (lang3). The prehash is computed either in one go
(Prehash) or from the message split into chunks (ChunkedPrehash).
"""

import os
import random
from typing import List

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
SUPPORTED_LANGUAGES = ['cc', 'go', 'python']
UNSUPPORTED_LANGUAGES = ['java']

# Languages that also support ChunkedPrehash.
CHUNKED_PREHASH_SUPPORTED_LANGUAGES = ['cc']
CHUNKED_PREHASH_UNSUPPORTED_LANGUAGES = ['go', 'java', 'python']


def _random_message() -> bytes:
  return os.urandom(random.choice([0, 1, 17, 31, 1027]))


def _split_into_random_chunks(message: bytes) -> List[bytes]:
  """Splits message into a random number of randomly sized chunks.

  Some of the chunks may be empty.

  Args:
    message: the message to split.

  Returns:
    A list of chunks whose concatenation is message.
  """
  num_chunks = random.randint(1, 5)
  cuts = sorted(random.randint(0, len(message)) for _ in range(num_chunks - 1))
  bounds = [0] + cuts + [len(message)]
  return [message[bounds[i] : bounds[i + 1]] for i in range(num_chunks)]


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
              message = _random_message()
              prehash = prehasher.compute_prehash(message)
              signature = signer.sign_prehash(prehash)
              verifier.verify(signature, message)

  def test_3way_chunked_external_mu_mldsa_consistency(self):
    """Chunked prehash in lang1, sign in lang2, verify in lang3."""
    for key in mldsa_keys.external_mu_mldsa_private_keys():
      for lang1 in CHUNKED_PREHASH_SUPPORTED_LANGUAGES:
        for lang2 in SUPPORTED_LANGUAGES:
          for lang3 in SUPPORTED_LANGUAGES:
            with self.subTest(f'{lang1}->{lang2}->{lang3}: {key}'):
              private_keyset = key.as_serialized_keyset()
              public_keyset = testing_servers.public_keyset(
                  lang1, private_keyset
              )
              chunked_prehasher = testing_servers.remote_primitive(
                  lang1, public_keyset, _primitives.ChunkedPrehash
              )
              signer = testing_servers.remote_primitive(
                  lang2, private_keyset, _primitives.PrehashSigner
              )
              verifier = testing_servers.remote_primitive(
                  lang3, public_keyset, tink.signature.PublicKeyVerify
              )
              message = _random_message()
              prehash = chunked_prehasher.compute_prehash(
                  _split_into_random_chunks(message)
              )
              signature = signer.sign_prehash(prehash)
              verifier.verify(signature, message)

  def test_chunked_prehash_matches_prehash(self):
    """The chunked prehash in lang1 equals the prehash computed in lang2."""
    for key in mldsa_keys.external_mu_mldsa_private_keys():
      for lang1 in CHUNKED_PREHASH_SUPPORTED_LANGUAGES:
        for lang2 in SUPPORTED_LANGUAGES:
          with self.subTest(f'{lang1}->{lang2}: {key}'):
            private_keyset = key.as_serialized_keyset()
            public_keyset = testing_servers.public_keyset(lang1, private_keyset)
            chunked_prehasher = testing_servers.remote_primitive(
                lang1, public_keyset, _primitives.ChunkedPrehash
            )
            prehasher = testing_servers.remote_primitive(
                lang2, public_keyset, _primitives.Prehash
            )
            message = _random_message()
            self.assertEqual(
                chunked_prehasher.compute_prehash(
                    _split_into_random_chunks(message)
                ),
                prehasher.compute_prehash(message),
            )

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
      for lang in CHUNKED_PREHASH_UNSUPPORTED_LANGUAGES:
        with self.subTest(f'ChunkedPrehash in {lang}'):
          with self.assertRaises(tink.TinkError):
            testing_servers.remote_primitive(
                lang, public_keyset, _primitives.ChunkedPrehash
            )


if __name__ == '__main__':
  absltest.main()
