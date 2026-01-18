/**
 * @file component.c
 * @author Jacob Doll
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2024 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "board_link.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include "simple_i2c_peripheral.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

// Includes from containerized build
#include "ectf_params.h"
#include "component_secrets.h"
#include "ectf_protocol.h"
#include "simple_crypto.h"

// Include cache disable
#include "Rand_lib.h"
#include "disable_cache.h"
#include "key_exchange.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/
// AES
#define AES_SIZE 16 // 16 bytes
#define RAND_Z_SIZE 8
#define RAND_Y_SIZE 8
uint8_t RAND_Y[RAND_Y_SIZE];
uint8_t RAND_Z[RAND_Z_SIZE];
uint8_t GLOBAL_KEY[AES_SIZE];

#define SESSION_KEY_LEN 16
#define ECTF_MAX_PAYLOAD (MAX_I2C_MESSAGE_LEN - (int)sizeof(ectf_msg_header_t) - ECTF_TAG_LEN)

typedef struct {
    uint8_t valid;
    uint8_t key[SESSION_KEY_LEN];
    uint32_t tx_counter;
    uint32_t rx_counter;
    uint8_t nonce_a[ECTF_NONCE_DATA_LEN];
} session_state_t;

static session_state_t session_state;

/******************************** TYPE DEFINITIONS
 * ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST,
    COMPONENT_CMD_SECURE_SEND_VALIDATE,
    COMPONENT_CMD_SECURE_SEND_CONFIMRED,
    COMPONENT_CMD_POSTBOOT_VALIDATE,
} component_cmd_t;

/******************************** TYPE DEFINITIONS
 * ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t comp_ID[4];
    uint8_t rand_z[RAND_Z_SIZE];
    uint8_t rand_y[RAND_Z_SIZE];
    uint8_t remain[MAX_I2C_MESSAGE_LEN - 21];
} message;

/********************************* FUNCTION DECLARATIONS
 * **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES
 * **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t string_buffer[MAX_I2C_MESSAGE_LEN - 21];

/********************************* UTILITIES **********************************/
void uint32_to_uint8(uint8_t str_uint8[4], uint32_t str_uint32) {
    for (int i = 0; i < 4; i++)
        str_uint8[i] = (uint8_t)(str_uint32 >> 8 * (3 - i)) & 0xFF;
}

void uint8_to_uint32(uint8_t str_uint8[4], uint32_t *str_uint32) {
    *str_uint32 = 0; // Initialize to zero
    for (int i = 0; i < 4; i++)
        *str_uint32 |= (uint32_t)str_uint8[i] << 8 * (3 - i);
}

/*Return 1 if the same and 0 if different*/
int uint8_uint32_cmp(uint8_t str_uint8[4], uint32_t str_uint32) {
    int counter = 0;
    for (int i = 0; i < 4; i++)
        if (str_uint8[i] == (uint8_t)(str_uint32 >> 8 * (3 - i)) & 0xFF)
            counter++;
    return counter == 4;
}

void uint8Arr_to_uint8Arr(uint8_t target[RAND_Z_SIZE],
                          uint8_t control[RAND_Z_SIZE]) {
    for (int i = 0; i < RAND_Z_SIZE; i++) {
        target[i] = control[i];
    }
}

int random_checker(uint8_t target[RAND_Z_SIZE], uint8_t control[RAND_Z_SIZE]) {
    for (int i = 0; i < RAND_Z_SIZE; i++) {
        if (target[i] != control[i]) {
            return 0;
        }
    }
    return 1;
}

static void build_nonce(uint32_t counter, uint32_t component_id, uint8_t direction,
                        uint8_t nonce[ECTF_NONCE_LEN]) {
    nonce[0] = (uint8_t)(counter >> 24);
    nonce[1] = (uint8_t)(counter >> 16);
    nonce[2] = (uint8_t)(counter >> 8);
    nonce[3] = (uint8_t)(counter);
    nonce[4] = (uint8_t)(component_id >> 24);
    nonce[5] = (uint8_t)(component_id >> 16);
    nonce[6] = (uint8_t)(component_id >> 8);
    nonce[7] = (uint8_t)(component_id);
    nonce[8] = direction;
    nonce[9] = 0;
    nonce[10] = 0;
    nonce[11] = 0;
}

static int send_secure_message(uint8_t msg_type, uint32_t counter,
                               const uint8_t *key, uint8_t direction,
                               const uint8_t *payload, uint16_t payload_len) {
    if (payload_len > ECTF_MAX_PAYLOAD) {
        return ERROR_RETURN;
    }

    ectf_msg_header_t header;
    header.magic = ECTF_MSG_MAGIC;
    header.version = ECTF_MSG_VERSION;
    header.msg_type = msg_type;
    header.component_id = COMPONENT_ID;
    header.counter = counter;
    header.payload_len = payload_len;

    uint8_t nonce[ECTF_NONCE_LEN];
    build_nonce(counter, COMPONENT_ID, direction, nonce);

    uint8_t buffer[MAX_I2C_MESSAGE_LEN];
    memcpy(buffer, &header, sizeof(header));

    int ret = aead_encrypt_gcm(key, nonce, sizeof(nonce), (uint8_t *)&header,
                               sizeof(header), payload, payload_len,
                               buffer + sizeof(header),
                               buffer + sizeof(header) + payload_len,
                               ECTF_TAG_LEN);
    if (ret != 0) {
        return ERROR_RETURN;
    }

    uint8_t total_len = (uint8_t)(sizeof(header) + payload_len + ECTF_TAG_LEN);
    send_packet_and_ack(total_len, buffer);
    return SUCCESS_RETURN;
}

static int receive_secure_message(uint8_t direction, const uint8_t *key,
                                  ectf_msg_header_t *header, uint8_t *payload,
                                  uint16_t *payload_len) {
    uint8_t buffer[MAX_I2C_MESSAGE_LEN];
    int len = wait_and_receive_packet(buffer);
    if (len <= 0) {
        return ERROR_RETURN;
    }
    if (len < (int)(sizeof(ectf_msg_header_t) + ECTF_TAG_LEN)) {
        return ERROR_RETURN;
    }
    memcpy(header, buffer, sizeof(*header));
    if (header->magic != ECTF_MSG_MAGIC || header->version != ECTF_MSG_VERSION) {
        return ERROR_RETURN;
    }
    if (header->component_id != COMPONENT_ID) {
        return ERROR_RETURN;
    }
    if (header->payload_len > ECTF_MAX_PAYLOAD) {
        return ERROR_RETURN;
    }
    if (len != (int)(sizeof(ectf_msg_header_t) + header->payload_len + ECTF_TAG_LEN)) {
        return ERROR_RETURN;
    }

    uint8_t nonce[ECTF_NONCE_LEN];
    build_nonce(header->counter, COMPONENT_ID, direction, nonce);
    int ret = aead_decrypt_gcm(key, nonce, sizeof(nonce), (uint8_t *)header,
                               sizeof(*header), buffer + sizeof(*header),
                               header->payload_len,
                               buffer + sizeof(*header) + header->payload_len,
                               ECTF_TAG_LEN, payload);
    if (ret != 0) {
        return ERROR_RETURN;
    }
    *payload_len = header->payload_len;
    return SUCCESS_RETURN;
}

static int derive_session_key(const uint8_t *nonce_a, const uint8_t *nonce_c,
                              uint8_t *session_key) {
    uint8_t info[ECTF_NONCE_DATA_LEN + ECTF_NONCE_DATA_LEN + 4 + 16];
    size_t offset = 0;
    memcpy(info + offset, nonce_a, ECTF_NONCE_DATA_LEN);
    offset += ECTF_NONCE_DATA_LEN;
    memcpy(info + offset, nonce_c, ECTF_NONCE_DATA_LEN);
    offset += ECTF_NONCE_DATA_LEN;
    info[offset++] = (uint8_t)(COMPONENT_ID >> 24);
    info[offset++] = (uint8_t)(COMPONENT_ID >> 16);
    info[offset++] = (uint8_t)(COMPONENT_ID >> 8);
    info[offset++] = (uint8_t)(COMPONENT_ID);
    memcpy(info + offset, COMPONENT_DEPLOYMENT_ID, 16);

    if (hkdf_sha256(COMPONENT_DEPLOYMENT_ID, 16, COMPONENT_KC, SESSION_KEY_LEN,
                    info, sizeof(info), session_key, SESSION_KEY_LEN) != 0) {
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

/******************************* POST BOOT FUNCTIONALITY
 * *********************************/
/**
 * @brief Secure Send
 *
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent
 *
 * Securely send data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
void secure_send(uint8_t *buffer, uint8_t len) {
    uint8_t challenge_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t answer_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    message *challenge = (message *)challenge_buffer;
    Rand_NASYC(RAND_Y, RAND_Y_SIZE);
    challenge->opcode = COMPONENT_CMD_POSTBOOT_VALIDATE;
    uint8Arr_to_uint8Arr(challenge->rand_y, RAND_Y);

    secure_send_packet_and_ack(challenge_buffer, GLOBAL_KEY);

    int len_ans =
        secure_timed_wait_and_receive_packet(answer_buffer, GLOBAL_KEY);
    if (len_ans == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    message *response_ans = (message *)answer_buffer;
    // compare cmd code
    if (response_ans->opcode != COMPONENT_CMD_POSTBOOT_VALIDATE) {
        return ERROR_RETURN;
    }

    // compare Z value
    int y_check = random_checker(response_ans->rand_y, RAND_Y);
    if (y_check != 1) {
        return ERROR_RETURN;
    }

    message *command = (message *)transmit_buffer;

    command->opcode = COMPONENT_CMD_POSTBOOT_VALIDATE;
    uint8Arr_to_uint8Arr(RAND_Z, response_ans->rand_z);
    uint8Arr_to_uint8Arr(command->rand_z, RAND_Z);
    uint8Arr_to_uint8Arr(command->rand_y, RAND_Y);
    for (int x = 0; x < len; x++) {
        command->remain[x] = buffer[x];
    }

    secure_send_packet_and_ack(transmit_buffer, GLOBAL_KEY);
}

/**
 * @brief Secure Receive
 *
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
int secure_receive(uint8_t *buffer) {
    uint8_t challenge_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t answer_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];

    int len_chlg = secure_wait_and_receive_packet(challenge_buffer, GLOBAL_KEY);
    if (len_chlg == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    message *challenge = (message *)challenge_buffer;
    // compare cmd code
    if (challenge->opcode != COMPONENT_CMD_POSTBOOT_VALIDATE) {
        return ERROR_RETURN;
    }

    message *answer = (message *)answer_buffer;

    Rand_NASYC(RAND_Y, RAND_Z_SIZE);
    uint8Arr_to_uint8Arr(RAND_Z, challenge->rand_z);
    answer->opcode = COMPONENT_CMD_POSTBOOT_VALIDATE;
    uint8Arr_to_uint8Arr(answer->rand_z, RAND_Z);
    uint8Arr_to_uint8Arr(answer->rand_y, RAND_Y);

    secure_send_packet_and_ack(answer_buffer, GLOBAL_KEY);
    ;

    int len_msg =
        secure_timed_wait_and_receive_packet(receive_buffer, GLOBAL_KEY);
    if (len_msg == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    message *command = (message *)receive_buffer;

    // compare cmd code
    if (command->opcode != COMPONENT_CMD_POSTBOOT_VALIDATE) {
        return ERROR_RETURN;
    }
    // compare Y value
    int y_check = random_checker(command->rand_y, RAND_Y);
    if (y_check != 1) {
        return ERROR_RETURN;
    }
    for (int x = 0; x < MAX_I2C_MESSAGE_LEN - 21; x++) {
        buffer[x] = command->remain[x];
    }

    return len_msg;
}

// Not sure what the component will send back to AP, for Now I Just assume the
// trasmit_buffer input will have the message already
void secure_receive_and_send(uint8_t *receive_buffer, uint8_t *transmit_buffer,
                             uint8_t len) {
    memset(receive_buffer, 0, 256); // Keep eye on all the memset method, Zuhair
                                    // says this could be error pron
    secure_wait_and_receive_packet(receive_buffer, GLOBAL_KEY);
    message *command = (message *)receive_buffer;
    Rand_NASYC(RAND_Y, RAND_Y_SIZE);
    uint8_t validate_buffer[MAX_I2C_MESSAGE_LEN];
    message *send_packet = (message *)validate_buffer;
    send_packet->opcode = COMPONENT_CMD_SECURE_SEND_VALIDATE;
    memcpy(send_packet->rand_z, command->rand_z, RAND_Z_SIZE);
    memcpy(send_packet->rand_y, RAND_Y, RAND_Y_SIZE);
    secure_send_packet_and_ack(validate_buffer, GLOBAL_KEY);
    memset(receive_buffer, 0, 256); // Keep eye on all the memset method, Zuhair
                                    // says this could be error pron
    if (secure_timed_wait_and_receive_packet(receive_buffer, GLOBAL_KEY) < 0) {
        printf(
            "Component transmitting failed, the transmitting takes too long");
        return;
    }
    command = (message *)receive_buffer;
    if (command->rand_y != RAND_Y) {
        printf("Component has received expired message");
    }
    send_packet = (message *)transmit_buffer;
    send_packet->opcode = COMPONENT_CMD_SECURE_SEND_CONFIMRED;
    memcpy(send_packet->rand_z, command->rand_z, RAND_Z_SIZE);
    secure_send_packet_and_ack(transmit_buffer, GLOBAL_KEY);
}
/******************************* FUNCTION DEFINITIONS
 * *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
#endif
}

// Handle a command from the AP
void component_process_cmd() {
    uint8_t buffer[MAX_I2C_MESSAGE_LEN];
    int len = wait_and_receive_packet(buffer);
    if (len <= 0) {
        return;
    }

    if (len < (int)(sizeof(ectf_msg_header_t) + ECTF_TAG_LEN)) {
        return;
    }

    ectf_msg_header_t header;
    memcpy(&header, buffer, sizeof(header));
    if (header.magic != ECTF_MSG_MAGIC || header.version != ECTF_MSG_VERSION) {
        return;
    }
    if (header.component_id != COMPONENT_ID) {
        return;
    }
    if (header.payload_len > ECTF_MAX_PAYLOAD) {
        return;
    }
    if (len != (int)(sizeof(header) + header.payload_len + ECTF_TAG_LEN)) {
        return;
    }

    const uint8_t *key = NULL;
    if (header.msg_type == ECTF_MSG_HELLO) {
        key = COMPONENT_KC;
    } else if (session_state.valid) {
        key = session_state.key;
    } else {
        return;
    }

    uint8_t nonce[ECTF_NONCE_LEN];
    build_nonce(header.counter, COMPONENT_ID, ECTF_DIR_AP_TO_COMP, nonce);

    uint8_t payload[ECTF_MAX_PAYLOAD];
    if (aead_decrypt_gcm(key, nonce, sizeof(nonce), (uint8_t *)&header,
                         sizeof(header), buffer + sizeof(header),
                         header.payload_len,
                         buffer + sizeof(header) + header.payload_len,
                         ECTF_TAG_LEN, payload) != 0) {
        return;
    }

    if (header.msg_type == ECTF_MSG_HELLO) {
        if (header.counter != 0 || header.payload_len != ECTF_NONCE_DATA_LEN) {
            return;
        }
        memcpy(session_state.nonce_a, payload, ECTF_NONCE_DATA_LEN);
        uint8_t nonce_c[ECTF_NONCE_DATA_LEN];
        Rand_NASYC(nonce_c, ECTF_NONCE_DATA_LEN);
        if (derive_session_key(session_state.nonce_a, nonce_c, session_state.key) != SUCCESS_RETURN) {
            return;
        }
        session_state.valid = 1;
        session_state.tx_counter = 0;
        session_state.rx_counter = 0;
        send_secure_message(ECTF_MSG_HELLO_RESP, 0, COMPONENT_KC,
                            ECTF_DIR_COMP_TO_AP, nonce_c, ECTF_NONCE_DATA_LEN);
        return;
    }

    if (!session_state.valid || header.counter <= session_state.rx_counter) {
        return;
    }
    session_state.rx_counter = header.counter;

    switch (header.msg_type) {
    case ECTF_MSG_BOOT_REQ: {
        char boot_msg[MAX_I2C_MESSAGE_LEN];
        size_t msg_len = strlen(COMPONENT_BOOT_MSG);
        if (msg_len > ECTF_MAX_PAYLOAD) {
            return;
        }
        memcpy(boot_msg, COMPONENT_BOOT_MSG, msg_len);
        session_state.tx_counter++;
        send_secure_message(ECTF_MSG_BOOT_RESP, session_state.tx_counter,
                            session_state.key, ECTF_DIR_COMP_TO_AP,
                            (uint8_t *)boot_msg, (uint16_t)msg_len);
        boot();
        break;
    }
    case ECTF_MSG_ATTEST_REQ: {
        char attest_msg[MAX_I2C_MESSAGE_LEN];
        int msg_len = snprintf(attest_msg, sizeof(attest_msg),
                               "LOC>%s\nDATE>%s\nCUST>%s\n", ATTESTATION_LOC,
                               ATTESTATION_DATE, ATTESTATION_CUSTOMER);
        if (msg_len < 0 || msg_len > ECTF_MAX_PAYLOAD) {
            return;
        }
        session_state.tx_counter++;
        send_secure_message(ECTF_MSG_ATTEST_RESP, session_state.tx_counter,
                            session_state.key, ECTF_DIR_COMP_TO_AP,
                            (uint8_t *)attest_msg, (uint16_t)msg_len);
        break;
    }
    default:
        break;
    }
}

// This if for the functionality of Boot
void process_boot() {
    // The AP requested a boot.
    // Validate the Component ID
    message *command = (message *)receive_buffer;

    if (uint8_uint32_cmp(command->comp_ID, COMPONENT_ID) != 1) {
        printf("The Component ID checks failed at the component sided");
        return;
    }
    // Validation passed
    // Starts Boot

    // Send Boot comfirmation message back to AP
    memset(transmit_buffer, 0, MAX_I2C_MESSAGE_LEN); // DO WE NEED THIS?
    message *send_packet = (message *)transmit_buffer;
    send_packet->opcode = COMPONENT_CMD_BOOT;
    memcpy(send_packet->rand_z, command->rand_z, RAND_Z_SIZE);
    uint32_to_uint8(send_packet->comp_ID, COMPONENT_ID);
    memcpy(send_packet->remain, COMPONENT_BOOT_MSG, sizeof(COMPONENT_BOOT_MSG));
    secure_send_packet_and_ack(transmit_buffer, GLOBAL_KEY);
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID

    message *command = (message *)receive_buffer;
    memset(transmit_buffer, 0, MAX_I2C_MESSAGE_LEN); // DO WE NEED THIS?
    message *send_packet = (message *)transmit_buffer;
    send_packet->opcode = COMPONENT_CMD_SCAN;
    memcpy(send_packet->rand_z, command->rand_z, RAND_Z_SIZE);
    uint32_t comp_id = COMPONENT_ID;
    uint32_to_uint8(send_packet->comp_ID, comp_id);
    send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, transmit_buffer);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data

    // Validate the Component ID; plaintext[1:4]
    message *command = (message *)receive_buffer;

    if (uint8_uint32_cmp(command->comp_ID, COMPONENT_ID) != 1) {
        printf("The Component ID checks failed at the component sided");
        return;
    }

    // Start to move atttestation data into the transmit_buffer
    memset(string_buffer, 0, MAX_I2C_MESSAGE_LEN - 21);
    uint8_t len =
        sprintf((char *)string_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) +
        1;

    // Move the cipher text into the transmit_buffer and reday for transfer
    memset(transmit_buffer, 0, MAX_I2C_MESSAGE_LEN); // DO WE NEED THIS?
    message *send_packet = (message *)transmit_buffer;
    send_packet->opcode = COMPONENT_CMD_ATTEST;
    memcpy(send_packet->rand_z, command->rand_z, RAND_Z_SIZE);
    uint32_to_uint8(send_packet->comp_ID, COMPONENT_ID);
    memcpy(send_packet->remain, string_buffer, sizeof(send_packet->remain));
    secure_send_packet_and_ack(transmit_buffer, GLOBAL_KEY);
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    // Disable the cache
    disable_cache();
    // Enable Global Interrupts
    __enable_irq();

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    memset(&session_state, 0, sizeof(session_state));

    LED_On(LED2);

    while (1) {
        component_process_cmd();
    }
}
