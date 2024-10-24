# Copyright 2022 Google LLC
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
"""Primitive Creation consistency tests."""

from typing import Any

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from tink.proto import tink_pb2
from cross_language import tink_config
from cross_language.util import test_keys
from cross_language.util import testing_servers
from cross_language.util import utilities

# We register the primitives here because creation of the keysets happens
# before "setUpModule" is called.
aead.register()
daead.register()
jwt.register_jwt_mac()
jwt.register_jwt_signature()
mac.register()
hybrid.register()
prf.register()
signature.register()
streaming_aead.register()


def setUpModule():
  testing_servers.start('primitive_creation')


def tearDownModule():
  testing_servers.stop()


UNDEFINED_PYTHON_TEMPLATES = ['X_AES_GCM_8_BYTE_SALT_NO_PREFIX']


def single_key_keysets():
  """Produces single key keysets which can be produced from a template.

  This does not produce keysets which have public keys.
  Yields:
    valid keysets generated from templates
  """
  for template_name, template in utilities.KEY_TEMPLATE.items():
    # TODO: b/361542355 - Remove this check once the template is defined in
    # Python.
    if template_name not in UNDEFINED_PYTHON_TEMPLATES:
      yield test_keys.new_or_stored_keyset(template)


def single_key_keysets_one_per_primitive():
  """Produces single key keysets which can be produced from a template.

  This does not produce keysets which have public keys.
  Yields:
    valid keysets generated from templates
  """
  yield test_keys.new_or_stored_keyset(aead.aead_key_templates.AES128_GCM)
  yield test_keys.new_or_stored_keyset(jwt.jwt_hs256_template())
  yield test_keys.new_or_stored_keyset(jwt.jwt_es256_template())
  yield test_keys.new_or_stored_keyset(
      daead.deterministic_aead_key_templates.AES256_SIV
  )
  yield test_keys.new_or_stored_keyset(
      hybrid.hybrid_key_templates.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305
  )
  yield test_keys.new_or_stored_keyset(
      mac.mac_key_templates.HMAC_SHA512_256BITTAG
  )
  yield test_keys.new_or_stored_keyset(prf.prf_key_templates.AES_CMAC)
  yield test_keys.new_or_stored_keyset(
      signature.signature_key_templates.ECDSA_P256_IEEE_P1363
  )
  yield test_keys.new_or_stored_keyset(
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB
  )


def named_testcases():
  case_num = 0
  for lang in utilities.ALL_LANGUAGES:
    for keyset in single_key_keysets():
      key_type = utilities.key_types_in_keyset(keyset)[0]
      primitive = tink_config.primitive_for_keytype(key_type)
      yield {
          'testcase_name':
              str(case_num) + '-' + lang + '-' + primitive.__name__ + '-' +
              utilities.key_types_in_keyset(keyset)[0],
          'lang':
              lang,
          'primitive':
              primitive,
          'keyset':
              keyset,
      }
      case_num += 1

  for lang in utilities.ALL_LANGUAGES:
    for keyset in single_key_keysets_one_per_primitive():
      for primitive in tink_config.all_primitives():
        yield {
            'testcase_name':
                str(case_num) + '-' + lang + '-' + primitive.__name__ + '-' +
                utilities.key_types_in_keyset(keyset)[0],
            'lang':
                lang,
            'primitive':
                primitive,
            'keyset':
                keyset,
        }
        case_num += 1


class SupportedKeyTypesTest(parameterized.TestCase):
  """Tests if creation of primitives succeeds as described in tink_config.

  This test tries to see if creation of primitives is consistent with what is
  configured in tink_config._key_types. For this, we enumerate as many triples
  (lang, keyset, primitive) as possible, and compute, for each of them, the
  expected result from the config, and the actual result by creating the
  primitive.
  """

  @parameterized.named_parameters(named_testcases())
  def test_create(self, lang: str, keyset: bytes, primitive: Any):
    """Tests primitive creation (see top level comment).

    This test should pass for every keyset, as long as the keyset can be
    correctly parsed.

    Args:
      lang: The language to test
      keyset: A byte string representing a keyset. The keyset needs to be valid.
      primitive: The primitive to try and instantiate
    """
    keytypes = utilities.key_types_in_keyset(keyset)
    keytype = keytypes[0]

    if (lang in tink_config.supported_languages_for_key_type(keytype) and
        primitive == tink_config.primitive_for_keytype(keytype)):
      _ = testing_servers.remote_primitive(lang, keyset, primitive)
    else:
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, keyset, primitive)

  @parameterized.named_parameters(named_testcases())
  def test_create_with_public_keyset(self, lang: str, keyset: bytes,
                                     primitive: Any):
    """Tests primitive creation, after getting a public keyset.

    It would be somewhat better if the test cases above produce all keysets --
    however, this currently doesn't happen.

    Args:
      lang: the language to use
      keyset: the serialized keyset, must be valid
      primitive: the primitive to test
    """
    try:
      public_keyset = testing_servers.public_keyset(lang, keyset)
    except tink.TinkError:
      self.skipTest('Cannot get the public keyset')

    keytypes = utilities.key_types_in_keyset(public_keyset)
    self.assertLen(keytypes, 1)
    keytype = keytypes[0]

    if (lang in tink_config.supported_languages_for_key_type(keytype) and
        primitive == tink_config.primitive_for_keytype(keytype)):
      _ = testing_servers.remote_primitive(lang, public_keyset, primitive)
    else:
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, public_keyset, primitive)

  @parameterized.named_parameters(named_testcases())
  def test_create_with_key_id_0(self, lang: str, keyset: bytes, primitive: Any):
    """Tests primitive creation when key ID is 0.

    Args:
      lang: The language to test
      keyset: A byte string representing a keyset. The keyset needs to be valid.
      primitive: The primitive to try and instantiate
    """
    keyset_proto = tink_pb2.Keyset.FromString(keyset)
    for key in keyset_proto.key:
      if key.key_id == keyset_proto.primary_key_id:
        key.key_id = 0
    keyset_proto.primary_key_id = 0
    modified_keyset = keyset_proto.SerializeToString()

    keytypes = utilities.key_types_in_keyset(keyset)
    keytype = keytypes[0]

    if (lang in tink_config.supported_languages_for_key_type(keytype) and
        primitive == tink_config.primitive_for_keytype(keytype)):
      _ = testing_servers.remote_primitive(lang, modified_keyset, primitive)
    else:
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, modified_keyset, primitive)

  def test_single_key_keysets_one_per_primitive_complete(self):
    """Checks that single_key_keysets_one_per_primitive is updated if needed.

    We could miss updating single_key_keysets_one_per_primitive when we add
    a primitive. However, this should really always give exactly one keyset
    per primitive (excluding public key primitives).
    """
    primitives = []
    for keyset in single_key_keysets_one_per_primitive():
      keytypes = utilities.key_types_in_keyset(keyset)
      keytype = keytypes[0]
      primitives += [tink_config.primitive_for_keytype(keytype)]
    primitives += [
        hybrid.HybridEncrypt,
        signature.PublicKeyVerify,
        jwt.JwtPublicKeyVerify,
    ]
    self.assertCountEqual(primitives, tink_config.all_primitives())


if __name__ == '__main__':
  absltest.main()
