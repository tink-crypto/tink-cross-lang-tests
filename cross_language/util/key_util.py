# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License")
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
r"""Custom Text-format functions for Tink Keys, Keysets and Key Templates.

Tink keys contain a serialized proto. Because we don't use any proto, the
text output of the proto library is not helpful. The function

key_util.text_format(msg: message.Message)

is similar to text_format.MessageToString(msg), but additionally output the
parsed serialized proto as a comment, which makes the proto human readable,
but keep them readable by machines. For example, the AES128_EAX template
looks like this:

type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey"
# value: [type.googleapis.com/google.crypto.tink.AesEaxKeyFormat] {
#   params {
#     iv_size: 16
#   }
#   key_size: 16
# }
value: "\n\002\010\020\020\020"
output_prefix_type: TINK


The function

assert_tink_proto_equal(self, a: message.Message, b: message.Message)

can be used in tests to assert that two protos must be equal. If they are
not equal, the function tries to output a meaningfull error message.
"""

import copy
from typing import Any, Optional

# copybara:tink_placeholder(encoder)
from google.protobuf import descriptor
from google.protobuf import message
from google.protobuf import text_encoding
from google.protobuf import text_format as proto_text_format
from tink.proto import aes_cmac_pb2
from tink.proto import aes_cmac_prf_pb2
from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_ctr_hmac_streaming_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_hkdf_streaming_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import aes_gcm_siv_pb2
from tink.proto import aes_siv_pb2
from tink.proto import chacha20_poly1305_pb2
from tink.proto import ecdsa_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import ed25519_pb2
from tink.proto import hkdf_prf_pb2
from tink.proto import hmac_pb2
from tink.proto import hmac_prf_pb2
from tink.proto import hpke_pb2
from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import jwt_rsa_ssa_pkcs1_pb2
from tink.proto import jwt_rsa_ssa_pss_pb2
from tink.proto import kms_aead_pb2
from tink.proto import kms_envelope_pb2
from tink.proto import rsa_ssa_pkcs1_pb2
from tink.proto import rsa_ssa_pss_pb2
from tink.proto import xchacha20_poly1305_pb2


TYPE_STRING = 9
TYPE_MESSAGE = 11
TYPE_BYTES = 12
TYPE_ENUM = 14
LABEL_REPEATED = 3

TYPE_PREFIX = 'type.googleapis.com/'


class KeyProto:
  """A map from type URLs to key protos and key format protos."""

  _from_url = {}
  _format_from_url = {}

  @classmethod
  def from_url(cls, type_url: str) -> Any:
    return cls._from_url[type_url]

  @classmethod
  def format_from_url(cls, type_url: str) -> Any:
    return cls._format_from_url[type_url]

  @classmethod
  def add_key_type(cls, key_type: Any, key_format_type: Any):
    type_url = TYPE_PREFIX + key_type.DESCRIPTOR.full_name
    cls._from_url[type_url] = key_type
    cls._format_from_url[type_url] = key_format_type


KeyProto.add_key_type(aes_eax_pb2.AesEaxKey, aes_eax_pb2.AesEaxKeyFormat)
KeyProto.add_key_type(aes_gcm_pb2.AesGcmKey, aes_gcm_pb2.AesGcmKeyFormat)
KeyProto.add_key_type(aes_gcm_siv_pb2.AesGcmSivKey,
                      aes_gcm_siv_pb2.AesGcmSivKeyFormat)
KeyProto.add_key_type(aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey,
                      aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKeyFormat)
KeyProto.add_key_type(chacha20_poly1305_pb2.ChaCha20Poly1305Key,
                      chacha20_poly1305_pb2.ChaCha20Poly1305KeyFormat)
KeyProto.add_key_type(xchacha20_poly1305_pb2.XChaCha20Poly1305Key,
                      xchacha20_poly1305_pb2.XChaCha20Poly1305KeyFormat)
KeyProto.add_key_type(aes_siv_pb2.AesSivKey, aes_siv_pb2.AesSivKeyFormat)
KeyProto.add_key_type(aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey,
                      aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKeyFormat)
KeyProto.add_key_type(aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey,
                      aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKeyFormat)
KeyProto.add_key_type(ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey,
                      ecies_aead_hkdf_pb2.EciesAeadHkdfKeyFormat)
KeyProto.add_key_type(ecies_aead_hkdf_pb2.EciesAeadHkdfPublicKey,
                      ecies_aead_hkdf_pb2.EciesAeadHkdfKeyFormat)
KeyProto.add_key_type(hpke_pb2.HpkePrivateKey, hpke_pb2.HpkeKeyFormat)
KeyProto.add_key_type(hpke_pb2.HpkePublicKey, hpke_pb2.HpkeKeyFormat)
KeyProto.add_key_type(aes_cmac_pb2.AesCmacKey, aes_cmac_pb2.AesCmacKeyFormat)
KeyProto.add_key_type(hmac_pb2.HmacKey, hmac_pb2.HmacKeyFormat)
KeyProto.add_key_type(ecdsa_pb2.EcdsaPrivateKey, ecdsa_pb2.EcdsaKeyFormat)
KeyProto.add_key_type(ecdsa_pb2.EcdsaPublicKey, ecdsa_pb2.EcdsaKeyFormat)
KeyProto.add_key_type(ed25519_pb2.Ed25519PrivateKey,
                      ed25519_pb2.Ed25519KeyFormat)
KeyProto.add_key_type(ed25519_pb2.Ed25519PublicKey,
                      ed25519_pb2.Ed25519KeyFormat)
KeyProto.add_key_type(rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey,
                      rsa_ssa_pkcs1_pb2.RsaSsaPkcs1KeyFormat)
KeyProto.add_key_type(rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey,
                      rsa_ssa_pkcs1_pb2.RsaSsaPkcs1KeyFormat)
KeyProto.add_key_type(rsa_ssa_pss_pb2.RsaSsaPssPrivateKey,
                      rsa_ssa_pss_pb2.RsaSsaPssKeyFormat)
KeyProto.add_key_type(rsa_ssa_pss_pb2.RsaSsaPssPublicKey,
                      rsa_ssa_pss_pb2.RsaSsaPssKeyFormat)
KeyProto.add_key_type(aes_cmac_prf_pb2.AesCmacPrfKey,
                      aes_cmac_prf_pb2.AesCmacPrfKeyFormat)
KeyProto.add_key_type(hmac_prf_pb2.HmacPrfKey, hmac_prf_pb2.HmacPrfKeyFormat)
KeyProto.add_key_type(hkdf_prf_pb2.HkdfPrfKey, hkdf_prf_pb2.HkdfPrfKeyFormat)
KeyProto.add_key_type(jwt_ecdsa_pb2.JwtEcdsaPrivateKey,
                      jwt_ecdsa_pb2.JwtEcdsaKeyFormat)
KeyProto.add_key_type(jwt_ecdsa_pb2.JwtEcdsaPublicKey,
                      jwt_ecdsa_pb2.JwtEcdsaKeyFormat)
KeyProto.add_key_type(jwt_hmac_pb2.JwtHmacKey, jwt_hmac_pb2.JwtHmacKeyFormat)
KeyProto.add_key_type(jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PrivateKey,
                      jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1KeyFormat)
KeyProto.add_key_type(jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PublicKey,
                      jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1KeyFormat)
KeyProto.add_key_type(jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPrivateKey,
                      jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssKeyFormat)
KeyProto.add_key_type(jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPublicKey,
                      jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssKeyFormat)
KeyProto.add_key_type(kms_aead_pb2.KmsAeadKey, kms_aead_pb2.KmsAeadKeyFormat)
KeyProto.add_key_type(kms_envelope_pb2.KmsEnvelopeAeadKey,
                      kms_envelope_pb2.KmsEnvelopeAeadKeyFormat)


def _text_format_field(value: Any,
                       field: descriptor.FieldDescriptor,
                       indent: str) -> str:
  """Returns a text formated proto field."""
  if field.type == TYPE_MESSAGE:
    output = [
        indent + field.name + ' {',
        _normalize_and_text_format_message(value, indent + '  '),
        indent + '}'
    ]
    return '\n'.join(output)
  elif field.type == TYPE_ENUM:
    value_name = field.enum_type.values_by_number[value].name
    return indent + field.name + ': ' + value_name
  elif field.type in [TYPE_STRING, TYPE_BYTES]:
    return (indent + field.name + ': "' + text_encoding.CEscape(value, False) +
            '"')
  else:
    return indent + field.name + ': ' + str(value)


def _normalize_and_text_format_message(msg: message.Message,
                                       indent: str) -> str:
  """Returns a text formated proto message and changes msg to be canonical.

  Args:
    msg: the proto to be formated.
    indent: the indentation prefix of each line in the output.

  Returns:
    A proto text format output, where serialized fields are deserialized in
    a comment.
  """
  output = []
  fields = msg.DESCRIPTOR.fields
  # special case for Tinks custom 'any' proto.
  if (msg.DESCRIPTOR.full_name == 'google.crypto.tink.KeyTemplate' or
      msg.DESCRIPTOR.full_name == 'google.crypto.tink.KeyData'):
    type_url = getattr(msg, 'type_url')  # Pytype requires to use getattr
    output.append(
        _text_format_field(type_url, fields[0], indent))
    value = getattr(msg, 'value')
    if msg.DESCRIPTOR.full_name == 'google.crypto.tink.KeyTemplate':
      # In KeyTemplates, type_url does not match the proto type used.
      proto_type = KeyProto.format_from_url(type_url)
    else:
      proto_type = KeyProto.from_url(type_url)
    # parse 'value' and text format the content in a comment.
    field_proto = proto_type.FromString(value)
    output.append(indent + '# value: [' + TYPE_PREFIX +
                  proto_type.DESCRIPTOR.full_name + '] {')
    formatted_message = _normalize_and_text_format_message(
        field_proto, indent + '#   ')
    if formatted_message:
      output.append(formatted_message)
    output.append(indent + '# }')
    # Serialize message again so it is canonicalized
    # We require here that proto serialization is in increasing field order
    # (Tink protos are basically unchangeable, so we don't need to worry about
    # unknown fields). This is not guaranteed by proto, but is currently the
    # case. If this ever changes we either hopefully have already a better
    # solution in Tink, or else the proto team provides us with a reflection
    # based API to do this (as they do in C++.) In this case, we simply use the
    # slow API here.
    value = field_proto.SerializeToString(deterministic = True)
    setattr(msg, 'value', value)
    output.append(
        _text_format_field(value, fields[1], indent))
    fields = fields[2:]
  for field in fields:
    if field.label == LABEL_REPEATED:
      for value in getattr(msg, field.name):
        output.append(_text_format_field(value, field, indent))
    else:
      output.append(
          _text_format_field(
              getattr(msg, field.name), field, indent))
  return '\n'.join(output)


def text_format(msg: message.Message) -> str:
  msgcopy = copy.deepcopy(msg)
  return _normalize_and_text_format_message(msgcopy, '')


def parse_text_format(serialized: str, msg: message.Message) -> None:
  # Different from binary parsing, text_format.Parse does not Clear the message.
  msg.Clear()
  proto_text_format.Parse(serialized, msg)
  serialized_copy = text_format(msg)
  assert serialized_copy == serialized, serialized_copy


def assert_tink_proto_equal(self,
                            a: message.Message,
                            b: message.Message,
                            msg: Optional[str] = None) -> None:
  """Fails with a useful error if a and b aren't equal."""
  a_copy = copy.deepcopy(a)
  b_copy = copy.deepcopy(b)

  self.assertMultiLineEqual(
      _normalize_and_text_format_message(a_copy, ''),
      _normalize_and_text_format_message(b_copy, ''),
      msg=msg)
