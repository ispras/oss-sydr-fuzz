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

char *get_part(char **p, size_t *size) {
    size_t psize = *size;
    for(size_t i = 0; i < *size; ++i) {
        if ((*p)[i] == '#') {
            psize = i;
            break;
        }
    }
    char *part = (char *)calloc((psize * 2 + 5), sizeof(*part)); // already null-terminated
    if (part == NULL) {
        return NULL;
    }
    jwt_Base64encode(part, *p, psize);
    jwt_base64uri_encode(part);
    *p += psize + 1; *size = *size > psize ? *size - psize - 1 : 0;
    return part;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *p = data;
    size_t p_size = size;
    jwt_t *jwt;
    const char *header = get_part(&p, &p_size);
    const char *body = get_part(&p, &p_size);
    const char *sign = get_part(&p, &p_size);
    const char *encoded = NULL;
    unsigned char *key = NULL;
    int key_len = 0;
    uint8_t *str = (uint8_t*)calloc(size * 2 + 3, sizeof(*str)); // already null-terminated
    
    if (str == NULL || header == NULL || body == NULL || sign == NULL) {
        goto fuzzer_end;
    }
    size_t header_size = strlen(header);
    size_t body_size = strlen(body);
    size_t sign_size = strlen(sign);
    memcpy(str, header, header_size);
    str[header_size] = '.';
    memcpy(str + header_size + 1, body, body_size);
    str[header_size] = '.';
    str[header_size + body_size + 1] = '.';
    memcpy(str + header_size + body_size + 2, sign, sign_size);

    if (jwt_decode(&jwt, str, "dummy", 5)) {
        goto fuzzer_end;
    }
    key_len = jwt->key_len; 
    key = calloc(key_len + 1, sizeof(*key));
    memcpy(key, jwt -> key, key_len);
    
    char *dumped = jwt_dump_str(jwt, 1);
    free(dumped);
    
    encoded = jwt_encode_str(jwt);
    if (encoded == NULL) {
        goto fuzzer_end;
    }

    jwt_free(jwt);
    jwt_decode(&jwt, encoded, key, key_len);

fuzzer_end:
    jwt_free(jwt);
    free(key);
    free(encoded);
    free(header);
    free(body);
    free(sign);
    free(str);
    return 0;
}
