import unittest
from base64 import b64decode

import kkdcpasn1


def decode(data):
    data = data.replace(b'\\n', b'')
    data = data.replace(b' ', b'')
    return b64decode(data)


class KKDCPASN1Tests(unittest.TestCase):
    realm = 'FREEIPA.LOCAL'

    asreq1 = decode(b"""
        MIHEoIGwBIGtAAAAqWqBpjCBo6EDAgEFogMCAQqjDjAMMAqhBAICAJWiAgQApIGGMIGDo
        AcDBQBAAAAQoRIwEKADAgEBoQkwBxsFYWRtaW6iDxsNRlJFRUlQQS5MT0NBTKMiMCCgAw
        IBAqEZMBcbBmtyYnRndBsNRlJFRUlQQS5MT0NBTKURGA8yMDE1MDUxNDEwNDIzOFqnBgI
        EEchjtagUMBICARICARECARACARcCARkCARqhDxsNRlJFRUlQQS5MT0NBTA==
    """)

    asreq2 = decode(b"""
        MIIBJaCCARAEggEMAAABCGqCAQQwggEAoQMCAQWiAwIBCqNrMGkwDaEEAgIAhaIFBANNS
        VQwTKEDAgECokUEQzBBoAMCARKiOgQ48A25MkXWM1ZrTvaYMJcbFX7Hp7JW11omIwqOQd
        SSGKVZ9mzYLuL19RRhX9xrXbQS0klXRVgRWHMwCqEEAgIAlaICBACkgYYwgYOgBwMFAEA
        AABChEjAQoAMCAQGhCTAHGwVhZG1pbqIPGw1GUkVFSVBBLkxPQ0FMoyIwIKADAgECoRkw
        FxsGa3JidGd0Gw1GUkVFSVBBLkxPQ0FMpREYDzIwMTUwNTE0MTA0MjM4WqcGAgRXSy38q
        BQwEgIBEgIBEQIBEAIBFwIBGQIBGqEPGw1GUkVFSVBBLkxPQ0FM
    """)

    tgsreq = decode(b"""
        MIIDxaCCA7AEggOsAAADqGyCA6QwggOgoQMCAQWiAwIBDKOCAxowggMWMIICL6EDAgEBo
        oICJgSCAiJuggIeMIICGqADAgEFoQMCAQ6iBwMFAAAAAACjggFGYYIBQjCCAT6gAwIBBa
        EPGw1GUkVFSVBBLkxPQ0FMoiIwIKADAgECoRkwFxsGa3JidGd0Gw1GUkVFSVBBLkxPQ0F
        Mo4IBADCB/aADAgESoQMCAQGigfAEge3ODJahLoTF0Xl+DeWdBqy79TSJv6+L23WEuBQi
        CnvmiLGxFhe/zuW6LN9O0Ekb3moX4qFKW7bF/gw0GuuMemkIjLaZ2M5mZiaQQ456fU5dA
        +ntLs8C407x3TVu68TM1aDvQgyKVpQgTdjxTZVmdinueIxOQ5z2nTIyjA9W94umGrPIcc
        sOfwvTEqyVpXrQcXr2tj/o/WcDLh/hHMhlHRBr9uLBLdVh2xR1yRbwe/n1UsXckxRi/A/
        +YgGSW7YDFBXij9RpGaE0bpa8e4u/EkcQEgu66nwVrfNs/TvsTJ1VnL5LpicDZvXzm0gO
        y3OkgbowgbegAwIBEqKBrwSBrIWE4ylyvY7JpiGCJQJKpv8sd3tFK054UTDvs1UuBAiWz
        IwNOddrdb4YKKGC/ce3e/sX+CBvISNPsOqX4skXK0gnMCJaCU6H1QKNeJu1TJm8GxPQ28
        1B8ZrCnv9Vzput0YIXAFK1eoAfe9qnJVktLL9uwYfV7D4GDU634KtEvPeDTBVMmTVXpUR
        5HIXiE4Qw6bON74Ssg4n8YDoO0ZXdOIOOUh1+soMoUzjg2XIwgeChBAICAIiigdcEgdSg
        gdEwgc6hFzAVoAMCARChDgQMmmZqel1e6bYuSZBxooGyMIGvoAMCARKigacEgaQwxX40v
        E6S6aNej2Siwkr/JA/70sbSoR8JrET9q6DW0rtawnOzKGYYSNEs8GLWgeSQaqIKuWXDuT
        R898vv3RYY4nn1wSNQFFSOHxaVqdRzY55Z7HbO7OPTyQhPI31f1m8Tuxl7kpMM74Yhypj
        iQCe8RHrJUyCQay8AonQY11pRvRlwzcnbrB5GhegVmtp1Qhtv0Lj//yLHZ4MdVh5FV2N2
        8odz7KR2MHSgBwMFAEABAACiDxsNRlJFRUlQQS5MT0NBTKMnMCWgAwIBAaEeMBwbBGh0d
        HAbFGlwYXNydi5mcmVlaXBhLmxvY2FspREYDzIwMTUwNTE0MTA0MjM4WqcGAgRVUzCzqB
        QwEgIBEgIBEQIBEAIBFwIBGQIBGqEPGw1GUkVFSVBBLkxPQ0FM
    """)

    kpasswdreq = decode(b"""
        MIICeKCCAmMEggJfAAACWwJbAAECAm6CAf4wggH6oAMCAQWhAwIBDqIHAwUAAAAAAKOCA
        UFhggE9MIIBOaADAgEFoQ8bDUZSRUVJUEEuTE9DQUyiHTAboAMCAQGhFDASGwZrYWRtaW
        4bCGNoYW5nZXB3o4IBADCB/aADAgESoQMCAQGigfAEge3swqU5Z7QS15Hf8+o9UPdl3H7
        Xx+ZpEsg2Fj9b0KB/xnnkbTbJs4oic8h30jOtVfq589lWN/jx3CIRdyPndTfJLZCQZN4Q
        sm6Gye/czzfMFtIOdYSdDL0EpW5/adRsbX253dxqy7431s9Jxsx4xXIowOkD/cCHcrAw3
        SLchLXVXGbgcnnphAo+po8cJ7omMF0c0F0eOplKQkbbjoNJSO/TeIQJdgmUrxpy9c8Uhc
        ScdkajtyxGD9YvXDc8Ik7OCFn03e9bd791qasiBSTgCjWjV3IvcDohjF/RpxftA5LxmGS
        /C1KSG1AZBqivSMOkgZ8wgZygAwIBEqKBlASBkerR33SV6Gv+yTLbqByadkgmCAu4w1ms
        NifEss5TAhcEJEnpyqPbZgMfvksc+ULsnsdzovskhd1NbhJx+f9B0mxUzpNw1uRXMVbNw
        FGUSlYwVr+h1Hzs7/PLSsRV/jPNA+kbqbTcIkPOWe8OGGWuvbp24w6yrY3rcUCbEfhs+m
        xuSIJwMDwEUb2GqRwTkBhCGgd1UTBPoAMCAQWhAwIBFaNDMEGgAwIBEqI6BDh433pZMyL
        WiOUtyZnqOyiMoCe7ulv7TVyE5PGccaA3vXPzzBwh5P9wEFDl0alUBuHOKgBbtzOAgKEP
        Gw1GUkVFSVBBLkxPQ0FM
    """)

    def assert_decode(self, data, expected_type):
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
        result1 = self.assert_decode(self.asreq1, 'asreq')
        self.assertEqual(result1.offset, 4)
        result2 = self.assert_decode(self.asreq2, 'asreq')
        self.assertEqual(result2.offset, 4)
        self.assertNotEqual(result1, result2)
        self.assertNotEqual(hash(result1), hash(result2))

    def test_tgsreq(self):
        result = self.assert_decode(self.tgsreq, 'tgsreq')
        self.assertEqual(result.offset, 4)

    def test_kpasswdreq(self):
        result = self.assert_decode(self.kpasswdreq, 'kpasswd')
        self.assertEqual(result.offset, 10)
        self.assertEqual(result.version, 0x0001)


if __name__ == "__main__":
    unittest.main()
