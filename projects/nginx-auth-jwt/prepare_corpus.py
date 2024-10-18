#! /usr/bin/env python3

import sys, os, shutil
import base64
from pathlib import Path

if len(sys.argv) < 3:
    print('Provide input and output dir')
    exit(1)

if not os.path.isdir(sys.argv[1]):
    print('Not a directory ' + sys.argv[1])
    exit(1)

if not os.path.exists(sys.argv[2]):
    os.makedirs(sys.argv[2])

if not os.path.isdir(sys.argv[2]):
    print('Not a directory ' + sys.argv[2])
    exit(1)

for jwt_file in Path(sys.argv[1]).glob('**/*.jwt'):
    with open(jwt_file, 'rb') as f:
        data = f.read()
    if data[-1] == 10:
        data = data[:-1]
    header, body, sign = data.split(b'.')
    header = base64.urlsafe_b64decode(header + b'=' * (4 - len(header) % 4))
    body = base64.urlsafe_b64decode(body + b'=' * (4 - len(body) % 4))
    sign = base64.urlsafe_b64decode(sign + b'=' * (4 - len(sign) % 4))
    
    jwtd = header + b'#' + body + b'#' + sign

    with open(os.path.join(sys.argv[2], jwt_file.name + 'd'), 'wb') as f:
        f.write(jwtd)


jwks = [*Path(sys.argv[1]).glob('**/*.json'), *Path(sys.argv[1]).glob('**/*.jwks')]
for jwk_file in jwks:
    if jwk_file.stat().st_size > 1:
        shutil.copy(jwk_file, sys.argv[2])
