/* Copyright (C) 2024 ISP RAS
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jwk.h>
#include <jwt/jwt.h>
#include <jwt/base64.h>
#include <jwt/jwt-private.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    jwks_t *p = jwks_import_string(data, size);
    if (p == NULL) {
        goto fuzzer_end;
    }
    jwks_fetch_by(p, "fuzz1");
    jwks_parameter_by(p, "fuzz2", "fuzz3");
    jwks_thumbprint_by(p, "fuzz4");
    jwks_free(p);
fuzzer_end:
    return 0;
}
