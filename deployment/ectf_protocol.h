#ifndef ECTF_PROTOCOL_H
#define ECTF_PROTOCOL_H

#include <stdint.h>

#define ECTF_MSG_MAGIC 0xECF1
#define ECTF_MSG_VERSION 1

#define ECTF_TAG_LEN 16
#define ECTF_NONCE_LEN 12
#define ECTF_NONCE_DATA_LEN 16

#define ECTF_DIR_AP_TO_COMP 0xA5
#define ECTF_DIR_COMP_TO_AP 0x5A

typedef enum {
    ECTF_MSG_HELLO = 0x01,
    ECTF_MSG_HELLO_RESP = 0x02,
    ECTF_MSG_BOOT_REQ = 0x10,
    ECTF_MSG_BOOT_RESP = 0x11,
    ECTF_MSG_ATTEST_REQ = 0x20,
    ECTF_MSG_ATTEST_RESP = 0x21,
} ectf_msg_type_t;

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;
    uint8_t version;
    uint8_t msg_type;
    uint32_t component_id;
    uint32_t counter;
    uint16_t payload_len;
} ectf_msg_header_t;
#pragma pack(pop)

#endif
