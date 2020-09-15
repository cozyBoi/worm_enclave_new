#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int compare_mac(const unsigned char* str1, const unsigned char* str2);
int compare_mac_and_save(const unsigned char* str1, const unsigned char* str2);
int save_file_info(const char* name, const char* attr, const int* dir, const int* ret, const int* mode);
void save_local_time(int time);
void get_socket(void* str1, void* str2);
void get_hms(void* hour, void* min, void* sec);
int compare_enclave_time(void);
int checker(unsigned char* sealed_data);
int verifier(const char* name, const char* attr, const int* retention, const int* dir, unsigned char* sealed_data);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_pass_string(unsigned char* str, int hash_value, int dir_index);
sgx_status_t SGX_CDECL ocall_print_hex(unsigned char* str, int len);
sgx_status_t SGX_CDECL ocall_set_file(char* name, char c1, int num, int num2);
sgx_status_t SGX_CDECL ocall_delete_file(const char* name, char c1, int num);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
