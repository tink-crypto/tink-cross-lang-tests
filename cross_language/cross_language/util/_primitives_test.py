# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.testing.cross_language.cross_language.util._primitives."""

import datetime
from unittest import mock

from absl.testing import absltest
import tink
from tink import jwt

from cross_language.util import _primitives
from protos import testing_api_pb2


class PrimitivesTest(absltest.TestCase):

  def test_split_merge_timestamp(self):
    dt = datetime.datetime.fromtimestamp(1234.5678, datetime.timezone.utc)
    seconds, nanos = _primitives.split_datetime(dt)
    self.assertEqual(seconds, 1234)
    self.assertEqual(nanos, 567800000)
    self.assertEqual(_primitives.to_datetime(seconds, nanos), dt)

  def test_raw_jwt_to_proto_to_verified_jwt(self):
    raw = jwt.new_raw_jwt(
        type_header='type_header',
        issuer='issuer',
        subject='subject',
        audiences=['audience1', 'audience2'],
        jwt_id='jwt_id',
        not_before=datetime.datetime.fromtimestamp(1234567.89,
                                                   datetime.timezone.utc),
        issued_at=datetime.datetime.fromtimestamp(2345678.9,
                                                  datetime.timezone.utc),
        expiration=datetime.datetime.fromtimestamp(3456789,
                                                   datetime.timezone.utc),
        custom_claims={
            'null': None,
            'string': 'aString',
            'number': 123.456,
            'integer': 123,
            'bool': True,
            'list': [None, True, 'foo', 42, {
                'pi': 3.14
            }],
            'obj': {
                'list': [1, 3.14],
                'null': None,
                'bool': False
            }
        })
    proto = _primitives.raw_jwt_to_proto(raw)
    verified = _primitives.proto_to_verified_jwt(proto)
    self.assertEqual(verified.type_header(), 'type_header')
    self.assertEqual(verified.issuer(), 'issuer')
    self.assertEqual(verified.subject(), 'subject')
    self.assertEqual(verified.audiences(), ['audience1', 'audience2'])
    self.assertEqual(verified.jwt_id(), 'jwt_id')
    self.assertEqual(
        verified.not_before(),
        datetime.datetime.fromtimestamp(1234567, datetime.timezone.utc))
    self.assertEqual(
        verified.issued_at(),
        datetime.datetime.fromtimestamp(2345678, datetime.timezone.utc))
    self.assertEqual(
        verified.expiration(),
        datetime.datetime.fromtimestamp(3456789, datetime.timezone.utc))
    self.assertEqual(
        verified.custom_claim_names(),
        {'null', 'string', 'number', 'integer', 'bool', 'list', 'obj'})
    self.assertIsNone(verified.custom_claim('null'))
    self.assertEqual(verified.custom_claim('string'), 'aString')
    self.assertEqual(verified.custom_claim('number'), 123.456)
    self.assertEqual(verified.custom_claim('integer'), 123)
    self.assertEqual(verified.custom_claim('bool'), True)
    self.assertEqual(verified.custom_claim('list'),
                     [None, True, 'foo', 42, {'pi': 3.14}])
    self.assertEqual(
        verified.custom_claim('obj'),
        {'list': [1, 3.14], 'null': None, 'bool': False})

  def test_empty_raw_jwt_to_proto_to_verified_jwt(self):
    raw = jwt.new_raw_jwt(without_expiration=True)
    proto = _primitives.raw_jwt_to_proto(raw)
    verified = _primitives.proto_to_verified_jwt(proto)
    self.assertFalse(verified.has_type_header())
    self.assertFalse(verified.has_issuer())
    self.assertFalse(verified.has_subject())
    self.assertFalse(verified.has_audiences())
    self.assertFalse(verified.has_jwt_id())
    self.assertFalse(verified.has_not_before())
    self.assertFalse(verified.has_issued_at())
    self.assertFalse(verified.has_expiration())
    self.assertEmpty(verified.custom_claim_names())

  def test_jwt_validator_to_proto(self):
    now = datetime.datetime.fromtimestamp(1234567.125, datetime.timezone.utc)
    validator = jwt.new_validator(
        expected_type_header='type_header',
        expected_issuer='issuer',
        expected_audience='audience',
        clock_skew=datetime.timedelta(seconds=123),
        fixed_now=now)
    proto = _primitives.jwt_validator_to_proto(validator)
    expected = testing_api_pb2.JwtValidator()
    expected.expected_type_header.value = 'type_header'
    expected.expected_issuer.value = 'issuer'
    expected.expected_audience.value = 'audience'
    expected.clock_skew.seconds = 123
    expected.now.seconds = 1234567
    expected.now.nanos = 125000000
    self.assertEqual(proto, expected)

  def test_empty_jwt_validator_to_proto(self):
    validator = jwt.new_validator()
    proto = _primitives.jwt_validator_to_proto(validator)
    expected = testing_api_pb2.JwtValidator()
    expected.clock_skew.seconds = 0
    self.assertEqual(proto, expected)

  def test_prehash_compute_prehash(self):
    mock_stub = mock.MagicMock()
    mock_stub.CreatePrehash.return_value = testing_api_pb2.CreationResponse()
    mock_stub.ComputePrehash.return_value = (
        testing_api_pb2.ComputePrehashResponse(prehash=b'prehash_bytes')
    )
    annotations = {'key': 'val'}
    prehasher = _primitives.Prehash(
        'cc', mock_stub, b'public_keyset', annotations=annotations
    )
    mock_stub.CreatePrehash.assert_called_once_with(
        testing_api_pb2.CreationRequest(
            annotated_keyset=testing_api_pb2.AnnotatedKeyset(
                serialized_keyset=b'public_keyset', annotations=annotations
            )
        )
    )
    res = prehasher.compute_prehash(b'message_data')
    self.assertEqual(res, b'prehash_bytes')
    mock_stub.ComputePrehash.assert_called_once_with(
        testing_api_pb2.ComputePrehashRequest(
            public_annotated_keyset=testing_api_pb2.AnnotatedKeyset(
                serialized_keyset=b'public_keyset', annotations=annotations
            ),
            data=b'message_data',
        )
    )

  def test_prehash_create_fails(self):
    mock_stub = mock.MagicMock()
    mock_stub.CreatePrehash.return_value = testing_api_pb2.CreationResponse(
        err='creation_failed'
    )
    with self.assertRaises(tink.TinkError):
      _primitives.Prehash('cc', mock_stub, b'public_keyset', annotations=None)

  def test_prehash_compute_fails(self):
    mock_stub = mock.MagicMock()
    mock_stub.CreatePrehash.return_value = testing_api_pb2.CreationResponse()
    mock_stub.ComputePrehash.return_value = (
        testing_api_pb2.ComputePrehashResponse(err='compute_failed')
    )
    prehasher = _primitives.Prehash(
        'cc', mock_stub, b'public_keyset', annotations=None
    )
    with self.assertRaises(tink.TinkError):
      prehasher.compute_prehash(b'message_data')

  def test_prehash_signer_sign_prehash(self):
    mock_stub = mock.MagicMock()
    mock_stub.CreatePrehashSigner.return_value = (
        testing_api_pb2.CreationResponse()
    )
    mock_stub.SignPrehash.return_value = testing_api_pb2.SignPrehashResponse(
        signature=b'signature_bytes'
    )
    annotations = {'key': 'val'}
    signer = _primitives.PrehashSigner(
        'cc', mock_stub, b'private_keyset', annotations=annotations
    )
    mock_stub.CreatePrehashSigner.assert_called_once_with(
        testing_api_pb2.CreationRequest(
            annotated_keyset=testing_api_pb2.AnnotatedKeyset(
                serialized_keyset=b'private_keyset', annotations=annotations
            )
        )
    )
    res = signer.sign_prehash(b'prehash_bytes')
    self.assertEqual(res, b'signature_bytes')
    mock_stub.SignPrehash.assert_called_once_with(
        testing_api_pb2.SignPrehashRequest(
            private_annotated_keyset=testing_api_pb2.AnnotatedKeyset(
                serialized_keyset=b'private_keyset', annotations=annotations
            ),
            prehash=b'prehash_bytes',
        )
    )

  def test_prehash_signer_create_fails(self):
    mock_stub = mock.MagicMock()
    mock_stub.CreatePrehashSigner.return_value = (
        testing_api_pb2.CreationResponse(err='creation_failed')
    )
    with self.assertRaises(tink.TinkError):
      _primitives.PrehashSigner(
          'cc', mock_stub, b'private_keyset', annotations=None
      )

  def test_prehash_signer_sign_fails(self):
    mock_stub = mock.MagicMock()
    mock_stub.CreatePrehashSigner.return_value = (
        testing_api_pb2.CreationResponse()
    )
    mock_stub.SignPrehash.return_value = testing_api_pb2.SignPrehashResponse(
        err='sign_failed'
    )
    signer = _primitives.PrehashSigner(
        'cc', mock_stub, b'private_keyset', annotations=None
    )
    with self.assertRaises(tink.TinkError):
      signer.sign_prehash(b'prehash_bytes')


if __name__ == '__main__':
  absltest.main()
