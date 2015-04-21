import io
import unittest
from binascii import unhexlify

import TL
from Crypto.Hash import SHA

class TLTest(unittest.TestCase):

    def test_serialize_method(self):
        """Test sample from [https://core.telegram.org/mtproto/samples-auth_key#1-request-for-p-q-authorization]"""
        nonce = unhexlify('3E0549828CCA27E966B301A48FECE2FC')
        serialized_result = TL.serialize_method('req_pq', nonce=nonce)
        true_result = unhexlify('789746603E0549828CCA27E966B301A48FECE2FC')
        self.assertEqual(serialized_result, true_result)

    def test_serialize_object(self):
        """Test sample from https://core.telegram.org/mtproto/samples-auth_key#4-encrypted-data-generation"""
        pq = unhexlify('17ED48941A08F981')
        p = unhexlify('494C553B')
        q = unhexlify('53911073')
        nonce = unhexlify('3E0549828CCA27E966B301A48FECE2FC')
        server_nonce = unhexlify('A5CF4D33F4A11EA877BA4AA573907330')
        new_nonce = unhexlify('311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D')
        serialized_result = TL.serialize_obj('p_q_inner_data',
                                             pq=pq,
                                             p=p,
                                             q=q,
                                             nonce=nonce,
                                             server_nonce=server_nonce,
                                             new_nonce=new_nonce)
        SHA_result = SHA.new(serialized_result).digest()
        true_result = unhexlify('db761c27718a2305044f71f2ad951629d78b2449')
        self.assertEqual(SHA_result, true_result)

    def test_deserialize(self):
        response_bytes = io.BytesIO(unhexlify('632416053E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA5739073300817ED48941A08F98100000015C4B51C01000000216BE86C022BB4C3'))
        deserialized_result = TL.deserialize(response_bytes)
        true_result = {'nonce': unhexlify('3E0549828CCA27E966B301A48FECE2FC'),
                       'server_nonce': unhexlify('A5CF4D33F4A11EA877BA4AA573907330'),
                       'pq': unhexlify('17ED48941A08F981'),
                       'server_public_key_fingerprints': [-4344800451088585951]}
        self.assertDictEqual(true_result, deserialized_result)

def suite():
    tests = ['test_serialize_method', 'test_serialize_object', 'test_deserialize']
    return unittest.TestSuite(map(TLTest, tests))

if __name__ == '__main__':
    # unittest.main()
    unittest.TextTestRunner().run(suite())
