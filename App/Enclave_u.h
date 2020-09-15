#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PASS_STRING_DEFINED__
#define OCALL_PASS_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pass_string, (unsigned char* str, int hash_value, int dir_index));
#endif
#ifndef OCALL_PRINT_HEX_DEFINED__
#define OCALL_PRINT_HEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_hex, (unsigned char* str, int len));
#endif
#ifndef OCALL_SET_FILE_DEFINED__
#define OCALL_SET_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_set_file, (char* name, char c1, int num, int num2));
#endif
#ifndef OCALL_DELETE_FILE_DEFINED__
#define OCALL_DELETE_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_delete_file, (const char* name, char c1, int num));
#endif

sgx_status_t compare_mac(sgx_enclave_id_t eid, int* retval, const unsigned char* str1, const unsigned char* str2);
sgx_status_t compare_mac_and_save(sgx_enclave_id_t eid, int* retval, const unsigned char* str1, const unsigned char* str2);
sgx_status_t save_file_info(sgx_enclave_id_t eid, int* retval, const char* name, const char* attr, const int* dir, const int* ret, const int* mode);
sgx_status_t save_local_time(sgx_enclave_id_t eid, int time);
sgx_status_t get_socket(sgx_enclave_id_t eid, void* str1, void* str2);
sgx_status_t get_hms(sgx_enclave_id_t eid, void* hour, void* min, void* sec);
sgx_status_t compare_enclave_time(sgx_enclave_id_t eid, int* retval);
sgx_status_t checker(sgx_enclave_id_t eid, int* retval, unsigned char* sealed_data);
sgx_status_t verifier(sgx_enclave_id_t eid, int* retval, const char* name, const char* attr, const int* retention, const int* dir, unsigned char* sealed_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
