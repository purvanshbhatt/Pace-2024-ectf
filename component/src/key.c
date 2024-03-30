#include "key.h" 
uint8_t KEY_SHARE[16] = { 0x9B, 0x91, 0xA4, 0x35, 0xCD, 0x16, 0xE3, 0x62, 0x76, 0x8B, 0xCA, 0x1B, 0x7E, 0xC3, 0xC4, 0xE2 };
const uint8_t MASK[16] = { 0x4B, 0xD0, 0x1F, 0xB1, 0xFB, 0xE2, 0xA4, 0x6F, 0x56, 0xE9, 0xD2, 0x67, 0xBB, 0x11, 0x29, 0xD4 };
const uint8_t FINAL_MASK[16] = { 0x36, 0x43, 0x6E, 0x96, 0xC3, 0xDD, 0xC1, 0x79, 0xA0, 0x89, 0xD0, 0x43, 0x13, 0x62, 0xBB, 0x7F };
