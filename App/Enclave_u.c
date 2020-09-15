#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_compare_mac_t {
	int ms_retval;
	const unsigned char* ms_str1;
	size_t ms_str1_len;
	const unsigned char* ms_str2;
	size_t ms_str2_len;
} ms_compare_mac_t;

typedef struct ms_compare_mac_and_save_t {
	int ms_retval;
	const unsigned char* ms_str1;
	size_t ms_str1_len;
	const unsigned char* ms_str2;
	size_t ms_str2_len;
} ms_compare_mac_and_save_t;

typedef struct ms_save_file_info_t {
	int ms_retval;
	const char* ms_name;
	size_t ms_name_len;
	const char* ms_attr;
	const int* ms_dir;
	const int* ms_ret;
	const int* ms_mode;
} ms_save_file_info_t;

typedef struct ms_save_local_time_t {
	int ms_time;
} ms_save_local_time_t;

typedef struct ms_get_socket_t {
	void* ms_str1;
	void* ms_str2;
} ms_get_socket_t;

typedef struct ms_get_hms_t {
	void* ms_hour;
	void* ms_min;
	void* ms_sec;
} ms_get_hms_t;

typedef struct ms_compare_enclave_time_t {
	int ms_retval;
} ms_compare_enclave_time_t;

typedef struct ms_checker_t {
	int ms_retval;
	unsigned char* ms_sealed_data;
} ms_checker_t;

typedef struct ms_verifier_t {
	int ms_retval;
	const char* ms_name;
	size_t ms_name_len;
	const char* ms_attr;
	const int* ms_retention;
	const int* ms_dir;
	unsigned char* ms_sealed_data;
} ms_verifier_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_pass_string_t {
	unsigned char* ms_str;
	int ms_hash_value;
	int ms_dir_index;
} ms_ocall_pass_string_t;

typedef struct ms_ocall_print_hex_t {
	unsigned char* ms_str;
	int ms_len;
} ms_ocall_print_hex_t;

typedef struct ms_ocall_set_file_t {
	char* ms_name;
	char ms_c1;
	int ms_num;
	int ms_num2;
} ms_ocall_set_file_t;

typedef struct ms_ocall_delete_file_t {
	const char* ms_name;
	char ms_c1;
	int ms_num;
} ms_ocall_delete_file_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pass_string(void* pms)
{
	ms_ocall_pass_string_t* ms = SGX_CAST(ms_ocall_pass_string_t*, pms);
	ocall_pass_string(ms->ms_str, ms->ms_hash_value, ms->ms_dir_index);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_hex(void* pms)
{
	ms_ocall_print_hex_t* ms = SGX_CAST(ms_ocall_print_hex_t*, pms);
	ocall_print_hex(ms->ms_str, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_set_file(void* pms)
{
	ms_ocall_set_file_t* ms = SGX_CAST(ms_ocall_set_file_t*, pms);
	ocall_set_file(ms->ms_name, ms->ms_c1, ms->ms_num, ms->ms_num2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_delete_file(void* pms)
{
	ms_ocall_delete_file_t* ms = SGX_CAST(ms_ocall_delete_file_t*, pms);
	ocall_delete_file(ms->ms_name, ms->ms_c1, ms->ms_num);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_Enclave = {
	5,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_pass_string,
		(void*)Enclave_ocall_print_hex,
		(void*)Enclave_ocall_set_file,
		(void*)Enclave_ocall_delete_file,
	}
};
sgx_status_t compare_mac(sgx_enclave_id_t eid, int* retval, const unsigned char* str1, const unsigned char* str2)
{
	sgx_status_t status;
	ms_compare_mac_t ms;
	ms.ms_str1 = str1;
	ms.ms_str1_len = str1 ? strlen(str1) + 1 : 0;
	ms.ms_str2 = str2;
	ms.ms_str2_len = str2 ? strlen(str2) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t compare_mac_and_save(sgx_enclave_id_t eid, int* retval, const unsigned char* str1, const unsigned char* str2)
{
	sgx_status_t status;
	ms_compare_mac_and_save_t ms;
	ms.ms_str1 = str1;
	ms.ms_str1_len = str1 ? strlen(str1) + 1 : 0;
	ms.ms_str2 = str2;
	ms.ms_str2_len = str2 ? strlen(str2) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t save_file_info(sgx_enclave_id_t eid, int* retval, const char* name, const char* attr, const int* dir, const int* ret, const int* mode)
{
	sgx_status_t status;
	ms_save_file_info_t ms;
	ms.ms_name = name;
	ms.ms_name_len = name ? strlen(name) + 1 : 0;
	ms.ms_attr = attr;
	ms.ms_dir = dir;
	ms.ms_ret = ret;
	ms.ms_mode = mode;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t save_local_time(sgx_enclave_id_t eid, int time)
{
	sgx_status_t status;
	ms_save_local_time_t ms;
	ms.ms_time = time;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_socket(sgx_enclave_id_t eid, void* str1, void* str2)
{
	sgx_status_t status;
	ms_get_socket_t ms;
	ms.ms_str1 = str1;
	ms.ms_str2 = str2;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_hms(sgx_enclave_id_t eid, void* hour, void* min, void* sec)
{
	sgx_status_t status;
	ms_get_hms_t ms;
	ms.ms_hour = hour;
	ms.ms_min = min;
	ms.ms_sec = sec;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t compare_enclave_time(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_compare_enclave_time_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t checker(sgx_enclave_id_t eid, int* retval, unsigned char* sealed_data)
{
	sgx_status_t status;
	ms_checker_t ms;
	ms.ms_sealed_data = sealed_data;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verifier(sgx_enclave_id_t eid, int* retval, const char* name, const char* attr, const int* retention, const int* dir, unsigned char* sealed_data)
{
	sgx_status_t status;
	ms_verifier_t ms;
	ms.ms_name = name;
	ms.ms_name_len = name ? strlen(name) + 1 : 0;
	ms.ms_attr = attr;
	ms.ms_retention = retention;
	ms.ms_dir = dir;
	ms.ms_sealed_data = sealed_data;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

