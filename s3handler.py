"""Zero dependency Python urllib handler interface to AWS S3.
"""

__all__ = ['S3Handler']
__version__ = '0.0.1'
__author__ = 'Charles Simpson'


import hashlib
import hmac
import os
from datetime import datetime
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, urlparse
from urllib.request import HTTPSHandler, Request


_ISO_DATETIME_FMT = '%Y%m%dT%H%M%SZ'
_ISO_DATE_FMT = '%Y%m%d'


def _hmac_sha256(key, strdata):
    return hmac.digest(key, bytes(strdata, 'utf-8'), 'sha256')


def _sha256_hexdigest(strdata):
    return hashlib.sha256(bytes(strdata or '', 'utf-8')).hexdigest()


class S3Handler(HTTPSHandler):
    """Handles AWS S3 URLs of the form `s3://<bucket>/<key>`.
    """

    def __init__(self, access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                 secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                 session_token=os.environ.get('AWS_SESSION_TOKEN'),
                 region='us-east-1',
                 endpoint=None):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.region = region
        self.endpoint = endpoint or f"s3.{region}.amazonaws.com"

        super(S3Handler, self).__init__()


    def s3_open(self, request):
        pr = urlparse(request.full_url)
        bucket = pr.netloc

        timestamp = datetime.utcnow()

        newurl = f"https://{bucket}.{self.endpoint}{pr.path}"
        if pr.query:
            newurl += "?" + pr.query

        new = Request(url=newurl, data=request.data, method=request.get_method())
        for key, val in request.header_items():
            new.add_header(key, val)

        new.add_header('Host', f"{bucket}.{self.endpoint}")
        new.add_header('x-amz-date', timestamp.strftime(_ISO_DATETIME_FMT))
        new.add_header('x-amz-content-sha256', _sha256_hexdigest(request.data))
        if self.session_token:
            new.add_header('x-amz-security-token', self.session_token)

        new.add_header('Authorization', self._authorization_header(new, timestamp))

        return self.parent.open(new, timeout=request.timeout)


    def _authorization_header(self, request, timestamp):
        credential = f"{self.access_key_id}/{self._scope(timestamp)}"
        signed_headers = ';'.join([hdr.lower() for (hdr, _) in sorted(request.header_items())]) 
        signature = self._sign_request(request, timestamp)

        return f"AWS4-HMAC-SHA256 Credential={credential},SignedHeaders={signed_headers},Signature={signature}"


    def _sign_request(self, request, timestamp):
        return _hmac_sha256(self._signing_key(timestamp),
                            self._string_to_sign(request, timestamp)).hex()


    def _string_to_sign(self, request, timestamp):
        canonical_request_digest = _sha256_hexdigest(self._canonical_request(request))

        return f"AWS4-HMAC-SHA256\n{timestamp.strftime(_ISO_DATETIME_FMT)}\n{self._scope(timestamp)}\n{canonical_request_digest}"


    def _scope(self, timestamp):
        return f"{timestamp.strftime(_ISO_DATE_FMT)}/{self.region}/s3/aws4_request"


    def _canonical_request(self, request):
        # Request Verb
        canonical_lines = [request.get_method()]

        # Canonical URI
        pr = urlparse(request.full_url)
        canonical_lines.append(quote(pr.path))

        # Canonical Query String
        qsl = sorted(parse_qsl(pr.query, keep_blank_values=True))
        canonical_lines.append('&'.join([f"{quote(key)}={quote(val)}" for (key, val) in qsl]))

        # Canonical Headers
        headers = sorted(request.header_items())
        canonical_headers = []
        signed_headers = []
        for key, val in sorted(request.header_items()):
            lkey = key.lower()
            canonical_headers.append(f"{lkey}:{val.strip()}\n")
            signed_headers.append(lkey)

        canonical_lines.append(''.join(canonical_headers))

        # Signed Headers
        canonical_lines.append(';'.join(signed_headers))
       
        # Hashed Payload
        canonical_lines.append(_sha256_hexdigest(request.data))

        return '\n'.join(canonical_lines)


    def _signing_key(self, timestamp):
        # See https://docs.aws.amazon.com/general/latest/gr/create-signed-request.html
        date_key = _hmac_sha256(bytes('AWS4' + self.secret_access_key, 'utf-8'),
                               timestamp.strftime(_ISO_DATE_FMT))
        region_key = _hmac_sha256(date_key, self.region)
        service_key = _hmac_sha256(region_key, 's3')
        
        return _hmac_sha256(service_key, 'aws4_request')
