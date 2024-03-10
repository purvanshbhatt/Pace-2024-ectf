#ifndef __BYTE_STREAM_XOR__
#define __BYTE_STREAM_XOR__

#include <stdbool.h> // For bool type

/**
 * @brief Performs secure XOR operation between two byte arrays in-place.
 *
 * @param arr1 Pointer to the first input byte array.
 * @param arr2 Pointer to the second input byte array.
 * @param size The number of bytes to XOR (must be the same for arr1 and arr2).
 * @param dest Pointer to the destination array where the result will be stored.
 *
 * @return true on success, false if arrays have different lengths or if null 
 *         pointers are provided.
 */
bool XOR_secure(unsigned char* arr1, unsigned char* arr2, int size, unsigned char* dest);

#endif 
