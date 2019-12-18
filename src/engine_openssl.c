/*
Copyright 2019 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uv_mbed/uv_mbed.h>

#if _WIN32
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#else
#include <unistd.h>
#endif

// inspired by https://golang.org/src/crypto/x509/root_linux.go
// Possible certificate files; stop after finding one.
const char *const caFiles[] = {
        "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
        "/etc/pki/tls/cacert.pem",                           // OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
        "/etc/ssl/cert.pem"                                  // macOS
};
#define NUM_CAFILES (sizeof(caFiles) / sizeof(char *))

struct openssl_context {
    // mbedtls_ssl_config config;
    // mbedtls_pk_context *own_key;
    // mbedtls_x509_crt *own_cert;
};

struct openssl_engine {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    BIO *in;
    BIO *out;
};

static int openssl_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);
static int openssl_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
            const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id);

static tls_engine *new_openssl_engine(void *ctx, const char *host);

static int openssl_set_fd(void *engine, int fd);
static tls_handshake_state openssl_hs_state(void *engine);
static tls_handshake_state openssl_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout);
static int openssl_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout);
static int openssl_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout);
static int openssl_close(void *engine, char *out, size_t *out_bytes, size_t maxout);
static void openssl_free(tls_engine *engine);
static void openssl_free_ctx(tls_context *ctx);

static tls_context_api openssl_context_api = {
        .new_engine = new_openssl_engine,
        .free_engine = openssl_free,
        .free_ctx = openssl_free_ctx,
        .set_own_cert = openssl_set_own_cert,
        .set_own_cert_pkcs11 = openssl_set_own_cert_p11,
};

static tls_engine_api openssl_engine_api = {
        .set_fd = openssl_set_fd,
        .handshake_state = openssl_hs_state,
        .handshake = openssl_continue_hs,
        .close = openssl_close,
        .write = openssl_write,
        .read = openssl_read,
};




void cleanup_openssl() {
    EVP_cleanup();
}

static void init_openssl() { 
    SSL_load_error_strings();	    // Bring in and register error messages
    SSL_library_init();             // Register the available SSL/TLS ciphers and digests
}

static SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();   // Create new client-method instance

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}


static tls_context *new_openssl_ctx(const char *ca, size_t ca_len) {

    tls_context *ctx = calloc(1, sizeof(tls_context));
    ctx->api = &openssl_context_api;
    
    init_openssl();

    SSL_CTX *ssl_ctx = create_context();

    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);  // handle selecting the right elliptic curves
    
    ctx->ctx = ssl_ctx;

    if (ca != NULL) {
        // int rc = mbedtls_x509_crt_parse(ca, ca, ca_len);
        // if (rc < 0) {
        //     char err[1024];
        //     mbedtls_strerror(rc, err, sizeof(err));
        //     fprintf(stderr, "mbedtls_engine: %s\n", err);
        //     mbedtls_x509_crt_init(ca);

        //     rc = mbedtls_x509_crt_parse_file(ca, cabuf);
        //     mbedtls_strerror(rc, err, sizeof(err));
        //     fprintf(stderr, "mbedtls_engine: %s\n", err);
        // }
    }
    else { // try loading default CA stores
#if _WIN32
        HCERTSTORE       hCertStore;
        PCCERT_CONTEXT   pCertContext = NULL;

        if (!(hCertStore = CertOpenSystemStore(0, "ROOT")))
        {
            printf("The first system store did not open.");
            return -1;
        }
        while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
            mbedtls_x509_crt_parse(ca, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
        }
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
#else
        for (size_t i = 0; i < NUM_CAFILES; i++) {
            if (access(caFiles[i], R_OK) != -1) {
                printf("new_openssl_ctx() calling SSL_CTX_use_certificate_chain_file() with '%s'\n", caFiles[i]);

                if (SSL_CTX_use_certificate_chain_file(ctx->ctx, caFiles[i]) <= 0) {
                    ERR_print_errors_fp(stderr);
                    exit(EXIT_FAILURE);
                }
                break;
            }
        }
#endif
    }

    return ctx;
}

tls_context *default_tls_context(const char *ca, size_t ca_len) {
    return new_openssl_ctx(ca, ca_len);
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);



static tls_engine *new_openssl_engine(void *ctx, const char *host) {

    SSL_CTX *ssl_ctx = ctx;

    tls_engine *engine = calloc(1, sizeof(tls_engine));
    struct openssl_engine *openssl_eng = calloc(1, sizeof(struct openssl_engine));
    engine->engine = openssl_eng;
    openssl_eng->ssl_ctx = ssl_ctx;
    openssl_eng->in = BIO_new(0);
    openssl_eng->out = BIO_new(0);
    engine->api = &openssl_engine_api;

    return engine;
}

static void openssl_free_ctx(tls_context *ctx) {
    struct mbedtls_context *c = ctx->ctx;
    free(c);
    free(ctx);
}

static void openssl_free(tls_engine *engine) {
    struct openssl_engine *e = engine->engine;
    BIO_free(e->in);
    BIO_free(e->out);

    SSL_CTX_free(e->ssl_ctx);

    free(e);
    free(engine);
}

static int openssl_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len) {
    // struct mbedtls_context *c = ctx;
    // c->own_key = calloc(1, sizeof(mbedtls_pk_context));
    // int rc = mbedtls_pk_parse_key(c->own_key, key_buf, key_len, NULL, 0);
    // if (rc < 0) {
    //     rc = mbedtls_pk_parse_keyfile(c->own_key, key_buf, NULL);
    //     if (rc < 0) {
    //         fprintf(stderr, "failed to load private key");
    //         mbedtls_pk_free(c->own_key);
    //         free(c->own_key);
    //         c->own_key = NULL;
    //         return TLS_ERR;
    //     }
    // }

    // c->own_cert = calloc(1, sizeof(mbedtls_x509_crt));
    // rc = mbedtls_x509_crt_parse(c->own_cert, cert_buf, cert_len);
    // if (rc < 0) {
    //     rc = mbedtls_x509_crt_parse_file(c->own_cert, cert_buf);
    //     if (rc < 0) {
    //         fprintf(stderr, "failed to load certificate");
    //         mbedtls_x509_crt_free(c->own_cert);
    //         free(c->own_cert);
    //         c->own_cert = NULL;

    //         mbedtls_pk_free(c->own_key);
    //         free(c->own_key);
    //         c->own_key = NULL;
    //         return TLS_ERR;
    //     }
    // }

    // mbedtls_ssl_conf_own_cert(&c->config, c->own_cert, c->own_key);
    return TLS_OK;
}

static int openssl_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
    const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id) {

    // struct mbedtls_context *c = ctx;
    // c->own_key = calloc(1, sizeof(mbedtls_pk_context));
    // int rc = mp11_load_key(c->own_key, pkcs11_lib, pin, slot, key_id);
    // if (rc != CKR_OK) {
    //     fprintf(stderr, "failed to load private key - %s", p11_strerror(rc));
    //     mbedtls_pk_free(c->own_key);
    //     free(c->own_key);
    //     c->own_key = NULL;
    //     return TLS_ERR;
    // }

    // c->own_cert = calloc(1, sizeof(mbedtls_x509_crt));
    // rc = mbedtls_x509_crt_parse(c->own_cert, cert_buf, cert_len);
    // if (rc < 0) {
    //     rc = mbedtls_x509_crt_parse_file(c->own_cert, cert_buf);
    //     if (rc < 0) {
    //         fprintf(stderr, "failed to load certificate");
    //         mbedtls_x509_crt_free(c->own_cert);
    //         free(c->own_cert);
    //         c->own_cert = NULL;

    //         mbedtls_pk_free(c->own_key);
    //         free(c->own_key);
    //         c->own_key = NULL;
    //         return TLS_ERR;
    //     }
    // }

    // mbedtls_ssl_conf_own_cert(&c->config, c->own_cert, c->own_key);
    return TLS_OK;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str) {
    ((void) level);
    printf("%s:%04d: %s", file, line, str);
    fflush(stdout);
}

static int openssl_set_fd(void *engine, int fd) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    eng->ssl = SSL_new(eng->ssl_ctx);   // create new SSL structure to hold the data for a TLS connection
    return SSL_set_fd(eng->ssl, fd);           // attach the socket descriptor to the SSL structure
}

static tls_handshake_state openssl_hs_state(void *engine) {
    return TLS_HS_CONTINUE;
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No certificates!\n");
}

static tls_handshake_state openssl_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout) {

    struct openssl_engine *eng = (struct openssl_engine *) engine;

    if ( SSL_connect(eng->ssl) == -1 ) {  /* perform the connection */
        ERR_print_errors_fp(stderr);
        return TLS_HS_ERROR;
    }
    
    // ShowCerts(eng->ssl);        // get any certificates

    return TLS_HS_COMPLETE;
}

static int openssl_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout) {

    struct openssl_engine *eng = (struct openssl_engine *) engine;

    int count = SSL_write(eng->ssl, data, data_len);   // encrypt & send message

    *out_bytes = count;

    return count;
}

static int openssl_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout) {

    struct openssl_engine *eng = (struct openssl_engine *) engine;

    int count = SSL_read(eng->ssl, out, maxout); // get reply & decrypt

    *out_bytes = count;

    if (count > 0) {
        return TLS_READ_AGAIN;
    }

    int err = SSL_get_error(eng->ssl, count);
    
    ERR_print_errors_fp(stderr);
    
    switch (err)
    {
        case SSL_ERROR_NONE:
        {
            // no real error, just try again...
            return TLS_READ_AGAIN;
            break;
        }   
        case SSL_ERROR_ZERO_RETURN: 
        {
            // peer disconnected...
            return TLS_EOF;
            break;
        }   
        case SSL_ERROR_WANT_READ: 
        {
            fd_set fds;
            struct timeval timeout;

            // no data available right now, wait a few seconds in case new data arrives...
            int sock = SSL_get_rfd(eng->ssl);
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            timeout.tv_sec = 10;

            err = select(sock+1, &fds, NULL, NULL, &timeout);

            if (err > 0)
                return TLS_READ_AGAIN; // more data to read...

            return TLS_EOF; // else give up
            break;
        }
        default:
        {
            printf("error %i:%i\n", count, err); 
            return TLS_ERR;
            break;
        }
    }

    return TLS_ERR; // shoudn't get here
}

static int openssl_close(void *engine, char *out, size_t *out_bytes, size_t maxout) {
    return 0;
}
