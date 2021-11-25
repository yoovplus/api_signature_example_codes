import base64
import hashlib
import hmac
import six

def sign(method, path, secret, timestamp, body):
    verb = method.upper()
    if six.PY2:
        content_digest = hashlib.sha256(bytes(body)).digest()
    else:
        content_digest = hashlib.sha256(bytes(body, 'utf-8')).digest()

    content_hash = base64.b64encode(content_digest).decode()

    string_to_sign = verb + '\n' + path + '\n' + \
        timestamp + '\n '+ content_hash

    if six.PY2:
        digest = hmac.new(bytes(secret), bytes(
            string_to_sign), hashlib.sha256).digest()
    else:
        digest = hmac.new(bytes(secret, 'utf-8'), bytes(
            string_to_sign, 'utf-8'), hashlib.sha256).digest()

    signature = base64.b64encode(digest).decode()

    return signature
