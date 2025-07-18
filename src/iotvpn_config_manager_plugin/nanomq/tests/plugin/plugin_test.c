#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libnanomq.h"

int test_nanomq_get_cfg() {
    char in[102400], out[102400] = {0};
    int ret = nanomq_get_cfg(NULL, out);
    if (ret != 0) {
        printf("nanomq_get_cfg failed: ret:%d, out:%s\n", ret, out);
        return 1;
    }
    printf("%s\n", out);

    return 0;
}

int test_nanomq_set_cfg() {
    int ret;
    size_t size = 0;
    char in[102400] = {0}, out[102400] = {0};
    FILE *fp = fopen("./testdata/nanomq_set_cfg.in.json", "r");
    if (fp == NULL) {
        perror("fopen error");
        exit(EXIT_FAILURE);
    }

    struct stat st;
    ret = fstat(fp->_fileno, &st);
    if (ret < 0) {
        perror("fstat error");
        exit(EXIT_FAILURE);
    }
    fread(in, 1, st.st_size, fp);

    ret = nanomq_set_cfg(in, out);
    if (ret != 0) {
        fprintf(stderr, "nanomq_set_cfg error: %d", ret);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int test_mqtt_auth_get_cfg() {
    char in[4096], out[4096] = {0};
    int ret = mqtt_auth_get_cfg(NULL, out);
    if (ret != 0) {
        printf("nanomq_get_cfg failed: ret=%d\n", ret);
        return 1;
    }
    printf("%s\n", out);

    return 0;
}

int test_mqtt_auth_set_cfg() {
    int ret;
    size_t size = 0;
    char in[4096] = {0}, out[4096] = {0};
    FILE *fp = fopen("./testdata/mqtt_auth_get_cfg.in.json", "r");
    if (fp == NULL) {
        perror("fopen error");
        exit(EXIT_FAILURE);
    }

    struct stat st;
    ret = fstat(fp->_fileno, &st);
    if (ret < 0) {
        perror("fstat error");
        exit(EXIT_FAILURE);
    }
    fread(in, 1, st.st_size, fp);

    ret = mqtt_auth_set_cfg(in, out);
    if (ret != 0) {
        fprintf(stderr, "nanomq_set_cfg error: %d", ret);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int main() {
    test_nanomq_get_cfg();
    test_nanomq_set_cfg();
    test_mqtt_auth_get_cfg();
    test_mqtt_auth_set_cfg();
}
