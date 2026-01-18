/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Rand_lib.h"
#include "aes.h"




// Includes from containerized build
#include "disable_cache.h"
#include "ectf_params.h"
#include "ap_secrets.h"
#include "ectf_protocol.h"

#include "simple_crypto.h"

#include "simple_flash.h"

/********************************* Global Variables **********************************/

// Flash Macros
#define FLASH_ADDR                                                             \
    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

// Secure Communication Macro
// data is the output
// 12 byte number
// data is the output
// 12 byte number
#define RAND_Z_SIZE 8
uint8_t RAND_Z[RAND_Z_SIZE];
uint8_t RAND_Y[RAND_Z_SIZE];

uint8_t CP_KEY1[17];
uint8_t CP_KEY2[17];

// AES Macros
#define AES_SIZE 16 // 16 bytes

uint8_t synthesized = 0; // when you initiate any command from the host machine, check if the
                         // thing is synthesized yet or not, if not, synthesize the whole thing.
uint8_t GLOBAL_KEY[AES_SIZE];
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

#define SESSION_KEY_LEN 16
#define MAX_AP_SESSIONS COMPONENT_CNT

typedef struct {
    uint32_t component_id;
    uint8_t valid;
    uint8_t key[SESSION_KEY_LEN];
    uint32_t tx_counter;
    uint32_t rx_counter;
    uint8_t nonce_a[ECTF_NONCE_DATA_LEN];
    uint8_t nonce_c[ECTF_NONCE_DATA_LEN];
} session_state_t;

static session_state_t sessions[MAX_AP_SESSIONS];
static uint8_t pin_failures = 0;
static uint8_t token_failures = 0;

/******************************** TYPE DEFINITIONS *********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.

// Data type for all commands
typedef struct {
    uint8_t opcode;
    uint8_t comp_ID[4];
    uint8_t rand_z[RAND_Z_SIZE];
    uint8_t rand_y[RAND_Z_SIZE];
    uint8_t remain[MAX_I2C_MESSAGE_LEN   - 21];
} message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

flash_entry flash_status;

// Datatype for commands sent to components
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

// forward declaration
int issue_cmd(i2c_addr_t addr, uint8_t *transmit, uint8_t *receive);
void flash_simple_init(void);
int flash_simple_erase_page(uint32_t address);
void flash_simple_read(uint32_t address, uint32_t *buffer, uint32_t size);
int flash_simple_write(uint32_t address, uint32_t *buffer, uint32_t size);
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key,
                uint8_t *ciphertext);

/********************************* UTILITIES **********************************/
//

/*Tested converters*/
void uint32_to_uint8(uint8_t str_uint8[4], uint32_t str_uint32) {
    for (int i = 0; i < 4; i++)
        str_uint8[i] = (uint8_t)(str_uint32 >> 8 * (3 - i)) & 0xFF;
}


void uint8_to_uint32(uint8_t str_uint8[4], uint32_t* str_uint32) {
    *str_uint32 = 0; // Initialize to zero
    for (int i = 0; i < 4; i++) *str_uint32 |= (uint32_t)str_uint8[i] << 8 * (3 - i);
}

/*Return 1 if the same and 0 if different*/
int uint8_uint32_cmp(uint8_t str_uint8[4], uint32_t str_uint32){
    int counter = 0;
    for(int i = 0; i < 4; i++)
        if(str_uint8[i] == (uint8_t)(str_uint32 >> 8 * (3 - i)) & 0xFF)
            counter++;
    return counter == 4;
}

void uint8Arr_to_uint8Arr(uint8_t target[RAND_Z_SIZE], uint8_t control[RAND_Z_SIZE]) {
    for (int i = 0; i < RAND_Z_SIZE; i++){
        target[i] = control[i];
    }
}

int random_checker(uint8_t target[RAND_Z_SIZE], uint8_t control[RAND_Z_SIZE]) {
    for (int i = 0; i < RAND_Z_SIZE; i++){
        if (target[i] != control[i]){
            return 0;
        }
    }
    return 1;
}

#define ECTF_MAX_PAYLOAD (MAX_I2C_MESSAGE_LEN - (int)sizeof(ectf_msg_header_t) - ECTF_TAG_LEN)

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
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

static session_state_t *get_session(uint32_t component_id) {
    for (unsigned i = 0; i < MAX_AP_SESSIONS; i++) {
        if (sessions[i].component_id == component_id) {
            return &sessions[i];
        }
    }
    return NULL;
}

static session_state_t *get_or_create_session(uint32_t component_id) {
    session_state_t *session = get_session(component_id);
    if (session != NULL) {
        return session;
    }
    for (unsigned i = 0; i < MAX_AP_SESSIONS; i++) {
        if (sessions[i].component_id == 0) {
            sessions[i].component_id = component_id;
            sessions[i].valid = 0;
            sessions[i].tx_counter = 0;
            sessions[i].rx_counter = 0;
            return &sessions[i];
        }
    }
    return NULL;
}

static const uint8_t *find_component_kc(uint32_t component_id) {
    for (unsigned i = 0; i < AP_COMPONENT_KEY_COUNT; i++) {
        if (AP_COMPONENT_KEYS[i].component_id == component_id) {
            return AP_COMPONENT_KEYS[i].kc;
        }
    }
    return NULL;
}

static int send_secure_message(i2c_addr_t addr, uint32_t component_id,
                               uint8_t msg_type, uint32_t counter,
                               const uint8_t *key, uint8_t direction,
                               const uint8_t *payload, uint16_t payload_len) {
    if (payload_len > ECTF_MAX_PAYLOAD) {
        return ERROR_RETURN;
    }

    ectf_msg_header_t header;
    header.magic = ECTF_MSG_MAGIC;
    header.version = ECTF_MSG_VERSION;
    header.msg_type = msg_type;
    header.component_id = component_id;
    header.counter = counter;
    header.payload_len = payload_len;

    uint8_t nonce[ECTF_NONCE_LEN];
    build_nonce(counter, component_id, direction, nonce);

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
    return send_packet(addr, total_len, buffer);
}

static int receive_secure_message(i2c_addr_t addr, uint8_t direction,
                                  const uint8_t *key, ectf_msg_header_t *header,
                                  uint8_t *payload, uint16_t *payload_len) {
    uint8_t buffer[MAX_I2C_MESSAGE_LEN];
    int len = poll_and_receive_packet(addr, buffer);
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
    if (header->payload_len > ECTF_MAX_PAYLOAD) {
        return ERROR_RETURN;
    }

    if (len != (int)(sizeof(ectf_msg_header_t) + header->payload_len + ECTF_TAG_LEN)) {
        return ERROR_RETURN;
    }

    uint8_t nonce[ECTF_NONCE_LEN];
    build_nonce(header->counter, header->component_id, direction, nonce);

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

static int derive_session_key(const uint8_t *kc, const uint8_t *nonce_a,
                              const uint8_t *nonce_c, uint32_t component_id,
                              uint8_t *session_key) {
    uint8_t info[ECTF_NONCE_DATA_LEN + ECTF_NONCE_DATA_LEN + 4 + 16];
    size_t offset = 0;
    memcpy(info + offset, nonce_a, ECTF_NONCE_DATA_LEN);
    offset += ECTF_NONCE_DATA_LEN;
    memcpy(info + offset, nonce_c, ECTF_NONCE_DATA_LEN);
    offset += ECTF_NONCE_DATA_LEN;
    info[offset++] = (uint8_t)(component_id >> 24);
    info[offset++] = (uint8_t)(component_id >> 16);
    info[offset++] = (uint8_t)(component_id >> 8);
    info[offset++] = (uint8_t)(component_id);
    memcpy(info + offset, AP_DEPLOYMENT_ID, 16);

    if (hkdf_sha256(AP_DEPLOYMENT_ID, 16, kc, SESSION_KEY_LEN, info,
                    sizeof(info), session_key, SESSION_KEY_LEN) != 0) {
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

static int establish_session(uint32_t component_id, session_state_t *session) {
    const uint8_t *kc = find_component_kc(component_id);
    if (kc == NULL) {
        return ERROR_RETURN;
    }

    Rand_NASYC(session->nonce_a, ECTF_NONCE_DATA_LEN);

    i2c_addr_t addr = component_id_to_i2c_addr(component_id);
    int send_res = send_secure_message(addr, component_id, ECTF_MSG_HELLO, 0,
                                       kc, ECTF_DIR_AP_TO_COMP,
                                       session->nonce_a, ECTF_NONCE_DATA_LEN);
    if (send_res < 0) {
        return ERROR_RETURN;
    }

    ectf_msg_header_t header;
    uint8_t payload[ECTF_MAX_PAYLOAD];
    uint16_t payload_len = 0;
    int recv_res = receive_secure_message(addr, ECTF_DIR_COMP_TO_AP, kc, &header,
                                          payload, &payload_len);
    if (recv_res != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    if (header.msg_type != ECTF_MSG_HELLO_RESP || header.counter != 0 ||
        header.component_id != component_id || payload_len != ECTF_NONCE_DATA_LEN) {
        return ERROR_RETURN;
    }

    memcpy(session->nonce_c, payload, ECTF_NONCE_DATA_LEN);
    if (derive_session_key(kc, session->nonce_a, session->nonce_c, component_id,
                           session->key) != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    session->valid = 1;
    session->tx_counter = 0;
    session->rx_counter = 0;
    return SUCCESS_RETURN;
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param transmit_buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t *buffer, uint8_t len) {
    uint8_t challenge_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t answer_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    message* challenge = (message*)challenge_buffer;
    Rand_NASYC(RAND_Z, RAND_Z_SIZE);
    challenge->opcode = COMPONENT_CMD_POSTBOOT_VALIDATE;
    uint8Arr_to_uint8Arr(challenge->rand_z, RAND_Z);

    int len_chlg = secure_send_packet(address, challenge_buffer, GLOBAL_KEY);
    if (len_chlg == ERROR_RETURN) {
        print_error("The AP failed to send the challenge buffer during post boot\n");
        return ERROR_RETURN;
    }
    
    int len_ans = secure_poll_and_receive_packet(address, answer_buffer, GLOBAL_KEY);
    if (len_ans == ERROR_RETURN) {
        print_error("The AP failed to receive the answer buffer during post boot\n");
        return ERROR_RETURN;
    }

    message* response_ans = (message*)answer_buffer;
    // compare cmd code
    if (response_ans->opcode != COMPONENT_CMD_POSTBOOT_VALIDATE) {
        print_error("Invalid command in answer message from component during post boot");
        return ERROR_RETURN;
    }

    // compare Z value
    int z_check = random_checker(response_ans->rand_z, RAND_Z);
    if (z_check != 1) {
        print_error("AP received expired answer message in post boot");
        return ERROR_RETURN;
    }

    message* command = (message*)transmit_buffer;

    uint8Arr_to_uint8Arr(RAND_Y, response_ans->rand_y);
    uint8Arr_to_uint8Arr(command->rand_z, RAND_Z);
    uint8Arr_to_uint8Arr(command->rand_y, RAND_Y);
    for(int x = 0; x < len; x++){
        command->remain[x] = buffer[x];
    }

    int len_msg = secure_send_packet(address, transmit_buffer, GLOBAL_KEY);
    if (len_msg == ERROR_RETURN) {
        print_error("The AP failed to send the buffer message during post boot\n");
        return ERROR_RETURN;
    }
    print_success("Secure Send Success\n");
    return len_msg;
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t *buffer) {
    uint8_t challenge_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t answer_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    
    int len_chlg = secure_poll_and_receive_packet(address, challenge_buffer, GLOBAL_KEY);
    if (len_chlg == ERROR_RETURN) {
        print_error("The AP failed to receive the challenge buffer during post boot\n");
        return ERROR_RETURN;
    }

    message* challenge = (message*)challenge_buffer;
    message* answer = (message*)answer_buffer;

    Rand_NASYC(RAND_Z, RAND_Z_SIZE);
    uint8Arr_to_uint8Arr(RAND_Y, challenge->rand_y);
    answer->opcode = COMPONENT_CMD_POSTBOOT_VALIDATE;
    uint8Arr_to_uint8Arr(answer->rand_z, RAND_Z);
    uint8Arr_to_uint8Arr(answer->rand_y, RAND_Y);

    int len_ans = secure_send_packet(address, answer_buffer, GLOBAL_KEY);
    if (len_ans == ERROR_RETURN) {
        print_error("The AP failed to send the answer message during post boot\n");
        return ERROR_RETURN;
    }

    int len_msg = secure_poll_and_receive_packet(address, receive_buffer, GLOBAL_KEY);
    if (len_msg == ERROR_RETURN) {
        print_error("The AP failed to receive the message buffer during post boot\n");
        return ERROR_RETURN;
    }

    message* command = (message*)receive_buffer;

    // compare cmd code
    if (command->opcode != COMPONENT_CMD_POSTBOOT_VALIDATE) {
        print_error("Invalid opcode in command message from component during post boot");
        return ERROR_RETURN;
    }
    // compare Z value
    int z_check = random_checker(command->rand_z, RAND_Z);
    if (z_check != 1) {
        print_error("AP received expired command message in post boot");
        return ERROR_RETURN;
    }
    for(int x = 0; x < MAX_I2C_MESSAGE_LEN-21; x++){
        buffer[x] = command->remain[x];
    }

    print_success("Secure Receive Success\n");
    return len_msg;
}

/**
 * @brief Get Provisioned IDs
 *
 * @param uint32_t* buffer
 *
 * @return int: number of ids
 *
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT
 * functionality. This function must be implemented by your team.
 */
int get_provisioned_ids(uint32_t *buffer) {
    memcpy(buffer, flash_status.component_ids,
           flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t *)&flash_status,
                      sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids,
               COMPONENT_CNT * sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                           sizeof(flash_entry));
    }

    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t *transmit, uint8_t *receive) {
    // Send message
    //These are reserved address for the Board, we should not use these
    if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            return ERROR_RETURN;
    }
    int result = secure_send_packet(addr, transmit, GLOBAL_KEY); 
    if (result == ERROR_RETURN) {
        print_info("Error in sending the packet\n");
        return ERROR_RETURN;
    }

    // Receive message
    int len = secure_poll_and_receive_packet(addr, receive, GLOBAL_KEY); // Use secure custom function
    if (len == ERROR_RETURN) {
        print_info("Error in receiving the packet\n");
        return ERROR_RETURN;
    }
    return len;
}

int insecure_issue_cmd(i2c_addr_t addr, uint8_t *transmit, uint8_t *receive) {
    // Send message
    //These are reserved address for the Board, we should not use these
    if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            return ERROR_RETURN;
    }
    int result = send_packet(addr, MAX_I2C_MESSAGE_LEN-1, transmit); 
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // Receive message
    int len = poll_and_receive_packet(addr, receive); // Use secure custom function
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

// We're assuming this doesn't need protection/modification
int scan_components() {
    int found = 0;
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        uint32_t component_id = flash_status.component_ids[i];
        print_info("P>0x%08x\n", component_id);

        session_state_t *session = get_or_create_session(component_id);
        if (session == NULL) {
            continue;
        }
        session->valid = 0;
        if (establish_session(component_id, session) == SUCCESS_RETURN) {
            print_info("F>0x%08x\n", component_id);
            found++;
        }
    }

    if (found == flash_status.component_cnt) {
        print_success("List\n");
        return SUCCESS_RETURN;
    }
    print_error("List\n");
    return ERROR_RETURN;
}

int validate_and_boot_components() {
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        uint32_t component_id = flash_status.component_ids[i];
        i2c_addr_t addr = component_id_to_i2c_addr(component_id);

        session_state_t *session = get_or_create_session(component_id);
        if (session == NULL ||
            (session->valid == 0 && establish_session(component_id, session) != SUCCESS_RETURN)) {
            print_error("Could not validate or boot component:%08x\n", component_id);
            return ERROR_RETURN;
        }

        session->tx_counter++;
        if (send_secure_message(addr, component_id, ECTF_MSG_BOOT_REQ,
                                session->tx_counter, session->key,
                                ECTF_DIR_AP_TO_COMP, NULL, 0) < 0) {
            print_error("Could not validate or boot component:%08x\n", component_id);
            return ERROR_RETURN;
        }

        ectf_msg_header_t header;
        uint8_t payload[ECTF_MAX_PAYLOAD + 1];
        uint16_t payload_len = 0;
        if (receive_secure_message(addr, ECTF_DIR_COMP_TO_AP, session->key,
                                   &header, payload, &payload_len) != SUCCESS_RETURN) {
            print_error("Could not validate or boot component:%08x\n", component_id);
            return ERROR_RETURN;
        }

        if (header.msg_type != ECTF_MSG_BOOT_RESP || header.component_id != component_id) {
            print_error("Invalid boot response from component\n");
            return ERROR_RETURN;
        }

        if (header.counter <= session->rx_counter) {
            print_error("Boot response replay detected\n");
            return ERROR_RETURN;
        }
        session->rx_counter = header.counter;

        payload[payload_len] = '\0';
        print_info("0x%08x>%s\n", component_id, payload);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    int provisioned = 0;
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id) {
            provisioned = 1;
            break;
        }
    }
    if (!provisioned) {
        print_error("Could not attest\n");
        return ERROR_RETURN;
    }

    session_state_t *session = get_or_create_session(component_id);
    if (session == NULL ||
        (session->valid == 0 && establish_session(component_id, session) != SUCCESS_RETURN)) {
        print_error("Could not attest\n");
        return ERROR_RETURN;
    }

    i2c_addr_t addr = component_id_to_i2c_addr(component_id);
    session->tx_counter++;
    if (send_secure_message(addr, component_id, ECTF_MSG_ATTEST_REQ,
                            session->tx_counter, session->key,
                            ECTF_DIR_AP_TO_COMP, NULL, 0) < 0) {
        print_error("Could not attest\n");
        return ERROR_RETURN;
    }

    ectf_msg_header_t header;
    uint8_t payload[ECTF_MAX_PAYLOAD + 1];
    uint16_t payload_len = 0;
    if (receive_secure_message(addr, ECTF_DIR_COMP_TO_AP, session->key,
                               &header, payload, &payload_len) != SUCCESS_RETURN) {
        print_error("Could not attest\n");
        return ERROR_RETURN;
    }
    if (header.msg_type != ECTF_MSG_ATTEST_RESP || header.component_id != component_id) {
        print_error("Could not attest\n");
        return ERROR_RETURN;
    }
    if (header.counter <= session->rx_counter) {
        print_error("Attestation response replay detected\n");
        return ERROR_RETURN;
    }
    session->rx_counter = header.counter;

    payload[payload_len] = '\0';
    print_info("C>0x%08x\n", component_id);
    print_info("%s", payload);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
// Example of how to utilize included simple_crypto.h
#ifdef CRYPTO_EXAMPLE
    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];

    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t *)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    uint8_t hash_out[HASH_SIZE];
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    print_hex_debug(hash_out, HASH_SIZE);

    // Decrypt the encrypted message and print out
    uint8_t decrypted[BLOCK_SIZE];
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    print_debug("Decrypted message: %s\r\n", decrypted);
#endif

// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[50];
    recv_input("Enter pin: ", buf);
    uint8_t hash_out[HASH_SIZE];
    size_t input_len = strnlen(buf, sizeof(buf));
    uint8_t data[sizeof(AP_PIN_SALT) + sizeof(buf)];
    memcpy(data, AP_PIN_SALT, sizeof(AP_PIN_SALT));
    memcpy(data + sizeof(AP_PIN_SALT), buf, input_len);
    hash_sha256(data, sizeof(AP_PIN_SALT) + input_len, hash_out);

    if (constant_time_equal(hash_out, AP_PIN_HASH, HASH_SIZE)) {
        pin_failures = 0;
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }

    pin_failures++;
    uint32_t delay = 200000 * pin_failures;
    if (delay > 2000000) {
        delay = 2000000;
    }
    MXC_Delay(delay);
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    uint8_t hash_out[HASH_SIZE];
    size_t input_len = strnlen(buf, sizeof(buf));
    uint8_t data[sizeof(AP_TOKEN_SALT) + sizeof(buf)];
    memcpy(data, AP_TOKEN_SALT, sizeof(AP_TOKEN_SALT));
    memcpy(data + sizeof(AP_TOKEN_SALT), buf, input_len);
    hash_sha256(data, sizeof(AP_TOKEN_SALT) + input_len, hash_out);

    if (constant_time_equal(hash_out, AP_TOKEN_HASH, HASH_SIZE)) {
        token_failures = 0;
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }

    token_failures++;
    uint32_t delay = 200000 * token_failures;
    if (delay > 2000000) {
        delay = 2000000;
    }
    MXC_Delay(delay);
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_and_boot_components()) {
        print_error("Failed to validate and/or boot components\n");
        return;
    }
    // print_info("All Components validated\n");

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    // Ensure replacement component is not already provisioned
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_in) {
            print_error("Component 0x%08x already provisioned\r\n", component_id_in);
            return;
        }
    }

    session_state_t *new_session = get_or_create_session(component_id_in);
    if (new_session == NULL || establish_session(component_id_in, new_session) != SUCCESS_RETURN) {
        print_error("Replacement component failed authentication\r\n");
        return;
    }

    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                               sizeof(flash_entry));

            session_state_t *old_session = get_session(component_id_out);
            if (old_session != NULL) {
                memset(old_session, 0, sizeof(session_state_t));
            }

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                        component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
                component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();
    memset(sessions, 0, sizeof(sessions));

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        memset(buf, 0, 100);
        recv_input("Enter Command: ", buf);

        if (!strcmp(buf, "list")) { // TODO: 3
            scan_components();
            continue;
        } 

        if (!strcmp(buf, "boot")) { // TODO: 4
            attempt_boot();
        } else if (!strcmp(buf, "replace")) { // TODO: 5
            attempt_replace();
        } else if (!strcmp(buf, "attest")) { // TODO: 6
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
