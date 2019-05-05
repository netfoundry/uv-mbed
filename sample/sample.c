//
// Created by eugene on 3/14/19.
//


#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <uv_mbed/uv_mbed.h>
#include "cmd_line_parser.h"

#define DEFAULT_CA_CHAIN "/etc/ssl/certs/ca-certificates.crt"

static void alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *p = (char *) calloc(suggested_size+1, sizeof(char));
    *buf = uv_buf_init(p, suggested_size);
}

static void on_close(uv_handle_t* h) {
    printf("mbed is closed\n");
    uv_mbed_free((uv_mbed_t *) h);
}

void on_data(uv_stream_t *h, ssize_t nread, const uv_buf_t* buf) {
    if (nread > 0) {
        printf("%*.*s", (int) nread, (int) nread, buf->base);
        fflush(stdout);
    } else if (nread == UV_EOF) {
        printf("=====================\nconnection closed\n");
        uv_mbed_close((uv_mbed_t *) h, on_close);
    } else {
        fprintf(stderr, "read error %ld: %s\n", nread, uv_strerror((int) nread));
        uv_mbed_close((uv_mbed_t *) h, on_close);
    }

    free(buf->base);
}

void write_cb(uv_write_t *wr, int status) {
    if (status < 0) {
        fprintf(stderr, "write failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close((uv_mbed_t *) wr->handle, on_close);
    }
    printf("request sent %d\n", status);
    free(wr);
}

void on_connect(uv_connect_t *cr, int status) {
    uv_mbed_t *mbed;
    uv_write_t *wr;
    struct cmd_line_info *cmd;
    char req[] = "GET %s HTTP/1.1\r\n"
                 "Accept: */*\r\n"
                 "Connection: keep-alive\r\n"
                 "Host: %s\r\n"
                 "User-Agent: HTTPie/1.0.2\r\n"
                 "\r\n";
    char out_buf[512];
    uv_buf_t buf;
    if (status < 0) {
        fprintf(stderr, "connect failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close((uv_mbed_t *) cr->handle, on_close);
        return;
    }

    mbed = (uv_mbed_t *) cr->handle;
    cmd = (struct cmd_line_info *)mbed->user_data;
    uv_mbed_read(mbed, alloc, on_data);

    wr = (uv_write_t *) calloc(1, sizeof(uv_write_t));

    sprintf(out_buf, req, cmd->request_path, cmd->server_addr);

    buf = uv_buf_init(out_buf, (unsigned int) strlen(out_buf) + 1);
    uv_mbed_write(wr, mbed, &buf, write_cb);
}

int main(int argc, char * const argv[]) {
    uv_loop_t *l = uv_default_loop();
    uv_mbed_t mbed;
    uv_connect_t cr;
    struct cmd_line_info *cmd;

    if (argc <= 1) {
        usage(argc, argv);
        return 0;
    }
    cmd = cmd_line_info_create(argc, argv);

    uv_mbed_init(l, &mbed);
    mbed.user_data = cmd;

    if (cmd->root_cert_file && strlen(cmd->root_cert_file)) {
        mbedtls_x509_crt *ca_chain;
        ca_chain = (mbedtls_x509_crt *) calloc(1, sizeof(mbedtls_x509_crt));
        mbedtls_x509_crt_parse_file(ca_chain, cmd->root_cert_file);
        uv_mbed_set_ca(&mbed, ca_chain);
    }

    uv_mbed_connect(&cr, &mbed, cmd->server_addr, atoi(cmd->server_port), on_connect);

    uv_run(l, UV_RUN_DEFAULT);

    cmd_line_info_destroy(cmd);
}
