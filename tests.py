import os
import unittest

import kkdcpasn1


HERE = os.path.dirname(os.path.abspath(__file__))
TESTCASES = os.path.abspath(os.path.join(HERE, 'testcases'))


class KKDCPASN1Tests(unittest.TestCase):
    realm = 'FREEIPA.LOCAL'

    def assert_decode(self, filename, expected_type):
        with open(os.path.join(TESTCASES, filename), 'rb') as f:
            data = f.read()

        result = kkdcpasn1.decode_kkdcp_request(data)
        self.assertEqual(result.realm, self.realm)
        self.assertEqual(result.dclocator_hint, 0)
        self.assertEqual(result.request_type, expected_type)
        self.assertTrue(repr(result))
        self.assertEqual(
            result.offset + result.consumed,
            len(result.request)
        )
        self.assertEqual(result, result)
        self.assertFalse(result != result)
        self.assertEqual(
            hash(result),
            hash(kkdcpasn1.decode_kkdcp_request(data))
        )
        # technically not correct, just for testing
        kkdcpasn1.wrap_kkdcp_response(result.request, True)
        return result

    def test_asreq(self):
        result1 = self.assert_decode('asreq1.der', 'asreq')
        self.assertEqual(result1.offset, 4)
        result2 = self.assert_decode('asreq2.der', 'asreq')
        self.assertEqual(result2.offset, 4)
        self.assertNotEqual(result1, result2)
        self.assertNotEqual(hash(result1), hash(result2))

    def test_tgsreq(self):
        result = self.assert_decode('tgsreq.der', 'tgsreq')
        self.assertEqual(result.offset, 4)

    def test_kpasswdreq(self):
        result = self.assert_decode('kpasswdreq.der', 'kpasswd')
        self.assertEqual(result.offset, 10)
        self.assertEqual(result.version, 0x0001)


if __name__ == "__main__":
    unittest.main()
