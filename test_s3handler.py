import hashlib
import unittest
from datetime import datetime
from urllib.request import Request

import s3handler


# Test cases taken from https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
EXAMPLE_AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
EXAMPLE_AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

class GetExampleSignatureTestCase(unittest.TestCase):
    def setUp(self):
        self.handler = s3handler.S3Handler(EXAMPLE_AWS_ACCESS_KEY_ID,
                                           EXAMPLE_AWS_SECRET_ACCESS_KEY,
                                           region='us-east-1')
        self.req = Request(url='https://examplebucket.s3.amazonaws.com/test.txt',
                      method='GET',
                      headers={'Host': 'examplebucket.s3.amazonaws.com',
                               'Range': 'bytes=0-9',
                               'x-amz-content-sha256': s3handler._sha256_hexdigest(''),
                               'x-amz-date': '20130524T000000Z'})

    def test_canonical_request(self):

        self.assertEqual(self.handler._canonical_request(self.req),
                          """GET
/test.txt

host:examplebucket.s3.amazonaws.com
range:bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20130524T000000Z

host;range;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""")


    def test_sign_request(self):
        self.assertEqual(self.handler._sign_request(self.req, datetime(2013, 5, 24)),
                         'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')


    def test_authorization_header(self):
        self.assertEqual(self.handler._authorization_header(self.req, datetime(2013, 5, 24)),
                         'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')


class PutExampleSignatureTestCase(unittest.TestCase):
    def setUp(self):
        self.handler = s3handler.S3Handler(EXAMPLE_AWS_ACCESS_KEY_ID,
                                           EXAMPLE_AWS_SECRET_ACCESS_KEY,
                                           region='us-east-1')

        data = "Welcome to Amazon S3."
        self.req = Request(url='https://examplebucket.s3.amazonaws.com/test$file.text',
                           method='PUT',
                           data=data,
                           headers={'Host': 'examplebucket.s3.amazonaws.com',
                                    'Date': 'Fri, 24 May 2013 00:00:00 GMT',
                                    'x-amz-date': '20130524T000000Z',
                                    'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                                    'x-amz-content-sha256': s3handler._sha256_hexdigest(data)})

    def test_canonical_request(self):
        self.assertEqual(self.handler._canonical_request(self.req),
                         """PUT
/test%24file.text

date:Fri, 24 May 2013 00:00:00 GMT
host:examplebucket.s3.amazonaws.com
x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072
x-amz-date:20130524T000000Z
x-amz-storage-class:REDUCED_REDUNDANCY

date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class
44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072""")


    def test_sign_request(self):
        self.assertEqual(self.handler._sign_request(self.req, datetime(2013, 5, 24)),
                         '98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd')


    def test_add_authorization_header(self):
        self.assertEqual(self.handler._authorization_header(self.req, datetime(2013, 5, 24)),
                         'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd')
    

if __name__ == '__main__':
    unittest.main()
