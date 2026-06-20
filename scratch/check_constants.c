#include <stdio.h>
#include <openssl/ssl.h>

int main() {
    printf("SSL_CTRL_SET_MIN_PROTO_VERSION: %d\n", SSL_CTRL_SET_MIN_PROTO_VERSION);
    printf("SSL_CTRL_SET_MAX_PROTO_VERSION: %d\n", SSL_CTRL_SET_MAX_PROTO_VERSION);
    printf("TLS1_3_VERSION: 0x%04X\n", TLS1_3_VERSION);
    return 0;
}
