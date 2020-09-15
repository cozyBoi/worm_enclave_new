#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_compare_mac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_compare_mac_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_compare_mac_t* ms = SGX_CAST(ms_compare_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_str1 = ms->ms_str1;
	size_t _len_str1 = ms->ms_str1_len ;
	unsigned char* _in_str1 = NULL;
	const unsigned char* _tmp_str2 = ms->ms_str2;
	size_t _len_str2 = ms->ms_str2_len ;
	unsigned char* _in_str2 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str1, _len_str1);
	CHECK_UNIQUE_POINTER(_tmp_str2, _len_str2);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str1 != NULL && _len_str1 != 0) {
		_in_str1 = (unsigned char*)malloc(_len_str1);
		if (_in_str1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str1, _len_str1, _tmp_str1, _len_str1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str1[_len_str1 - 1] = '\0';
		if (_len_str1 != strlen(_in_str1) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str2 != NULL && _len_str2 != 0) {
		_in_str2 = (unsigned char*)malloc(_len_str2);
		if (_in_str2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str2, _len_str2, _tmp_str2, _len_str2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str2[_len_str2 - 1] = '\0';
		if (_len_str2 != strlen(_in_str2) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = compare_mac((const unsigned char*)_in_str1, (const unsigned char*)_in_str2);

err:
	if (_in_str1) free(_in_str1);
	if (_in_str2) free(_in_str2);
	return status;
}

static sgx_status_t SGX_CDECL sgx_compare_mac_and_save(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_compare_mac_and_save_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_compare_mac_and_save_t* ms = SGX_CAST(ms_compare_mac_and_save_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_str1 = ms->ms_str1;
	size_t _len_str1 = ms->ms_str1_len ;
	unsigned char* _in_str1 = NULL;
	const unsigned char* _tmp_str2 = ms->ms_str2;
	size_t _len_str2 = ms->ms_str2_len ;
	unsigned char* _in_str2 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str1, _len_str1);
	CHECK_UNIQUE_POINTER(_tmp_str2, _len_str2);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str1 != NULL && _len_str1 != 0) {
		_in_str1 = (unsigned char*)malloc(_len_str1);
		if (_in_str1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str1, _len_str1, _tmp_str1, _len_str1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str1[_len_str1 - 1] = '\0';
		if (_len_str1 != strlen(_in_str1) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_str2 != NULL && _len_str2 != 0) {
		_in_str2 = (unsigned char*)malloc(_len_str2);
		if (_in_str2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str2, _len_str2, _tmp_str2, _len_str2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str2[_len_str2 - 1] = '\0';
		if (_len_str2 != strlen(_in_str2) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = compare_mac_and_save((const unsigned char*)_in_str1, (const unsigned char*)_in_str2);

err:
	if (_in_str1) free(_in_str1);
	if (_in_str2) free(_in_str2);
	return status;
}

static sgx_status_t SGX_CDECL sgx_save_file_info(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_save_file_info_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_save_file_info_t* ms = SGX_CAST(ms_save_file_info_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_name = ms->ms_name;
	size_t _len_name = ms->ms_name_len ;
	char* _in_name = NULL;
	const char* _tmp_attr = ms->ms_attr;
	size_t _len_attr = sizeof(char);
	char* _in_attr = NULL;
	const int* _tmp_dir = ms->ms_dir;
	size_t _len_dir = sizeof(int);
	int* _in_dir = NULL;
	const int* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(int);
	int* _in_ret = NULL;
	const int* _tmp_mode = ms->ms_mode;
	size_t _len_mode = sizeof(int);
	int* _in_mode = NULL;

	CHECK_UNIQUE_POINTER(_tmp_name, _len_name);
	CHECK_UNIQUE_POINTER(_tmp_attr, _len_attr);
	CHECK_UNIQUE_POINTER(_tmp_dir, _len_dir);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);
	CHECK_UNIQUE_POINTER(_tmp_mode, _len_mode);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_name != NULL && _len_name != 0) {
		_in_name = (char*)malloc(_len_name);
		if (_in_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_name, _len_name, _tmp_name, _len_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_name[_len_name - 1] = '\0';
		if (_len_name != strlen(_in_name) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_attr != NULL && _len_attr != 0) {
		if ( _len_attr % sizeof(*_tmp_attr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_attr = (char*)malloc(_len_attr);
		if (_in_attr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_attr, _len_attr, _tmp_attr, _len_attr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dir != NULL && _len_dir != 0) {
		if ( _len_dir % sizeof(*_tmp_dir) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_dir = (int*)malloc(_len_dir);
		if (_in_dir == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dir, _len_dir, _tmp_dir, _len_dir)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ( _len_ret % sizeof(*_tmp_ret) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ret = (int*)malloc(_len_ret);
		if (_in_ret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ret, _len_ret, _tmp_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mode != NULL && _len_mode != 0) {
		if ( _len_mode % sizeof(*_tmp_mode) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mode = (int*)malloc(_len_mode);
		if (_in_mode == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mode, _len_mode, _tmp_mode, _len_mode)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = save_file_info((const char*)_in_name, (const char*)_in_attr, (const int*)_in_dir, (const int*)_in_ret, (const int*)_in_mode);

err:
	if (_in_name) free(_in_name);
	if (_in_attr) free(_in_attr);
	if (_in_dir) free(_in_dir);
	if (_in_ret) free(_in_ret);
	if (_in_mode) free(_in_mode);
	return status;
}

static sgx_status_t SGX_CDECL sgx_save_local_time(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_save_local_time_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_save_local_time_t* ms = SGX_CAST(ms_save_local_time_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	save_local_time(ms->ms_time);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_socket(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_socket_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_socket_t* ms = SGX_CAST(ms_get_socket_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_str1 = ms->ms_str1;
	void* _tmp_str2 = ms->ms_str2;



	get_socket(_tmp_str1, _tmp_str2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_hms(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_hms_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_hms_t* ms = SGX_CAST(ms_get_hms_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_hour = ms->ms_hour;
	void* _tmp_min = ms->ms_min;
	void* _tmp_sec = ms->ms_sec;



	get_hms(_tmp_hour, _tmp_min, _tmp_sec);


	return status;
}

static sgx_status_t SGX_CDECL sgx_compare_enclave_time(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_compare_enclave_time_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_compare_enclave_time_t* ms = SGX_CAST(ms_compare_enclave_time_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = compare_enclave_time();


	return status;
}

static sgx_status_t SGX_CDECL sgx_checker(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_checker_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_checker_t* ms = SGX_CAST(ms_checker_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _len_sealed_data = 633;
	unsigned char* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (unsigned char*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = checker(_in_sealed_data);

err:
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_verifier(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verifier_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_verifier_t* ms = SGX_CAST(ms_verifier_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_name = ms->ms_name;
	size_t _len_name = ms->ms_name_len ;
	char* _in_name = NULL;
	const char* _tmp_attr = ms->ms_attr;
	size_t _len_attr = sizeof(char);
	char* _in_attr = NULL;
	const int* _tmp_retention = ms->ms_retention;
	size_t _len_retention = sizeof(int);
	int* _in_retention = NULL;
	const int* _tmp_dir = ms->ms_dir;
	size_t _len_dir = sizeof(int);
	int* _in_dir = NULL;
	unsigned char* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _len_sealed_data = 633;
	unsigned char* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_name, _len_name);
	CHECK_UNIQUE_POINTER(_tmp_attr, _len_attr);
	CHECK_UNIQUE_POINTER(_tmp_retention, _len_retention);
	CHECK_UNIQUE_POINTER(_tmp_dir, _len_dir);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_name != NULL && _len_name != 0) {
		_in_name = (char*)malloc(_len_name);
		if (_in_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_name, _len_name, _tmp_name, _len_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_name[_len_name - 1] = '\0';
		if (_len_name != strlen(_in_name) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_attr != NULL && _len_attr != 0) {
		if ( _len_attr % sizeof(*_tmp_attr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_attr = (char*)malloc(_len_attr);
		if (_in_attr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_attr, _len_attr, _tmp_attr, _len_attr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_retention != NULL && _len_retention != 0) {
		if ( _len_retention % sizeof(*_tmp_retention) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_retention = (int*)malloc(_len_retention);
		if (_in_retention == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_retention, _len_retention, _tmp_retention, _len_retention)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dir != NULL && _len_dir != 0) {
		if ( _len_dir % sizeof(*_tmp_dir) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_dir = (int*)malloc(_len_dir);
		if (_in_dir == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dir, _len_dir, _tmp_dir, _len_dir)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (unsigned char*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = verifier((const char*)_in_name, (const char*)_in_attr, (const int*)_in_retention, (const int*)_in_dir, _in_sealed_data);

err:
	if (_in_name) free(_in_name);
	if (_in_attr) free(_in_attr);
	if (_in_retention) free(_in_retention);
	if (_in_dir) free(_in_dir);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_compare_mac, 0, 0},
		{(void*)(uintptr_t)sgx_compare_mac_and_save, 0, 0},
		{(void*)(uintptr_t)sgx_save_file_info, 0, 0},
		{(void*)(uintptr_t)sgx_save_local_time, 0, 0},
		{(void*)(uintptr_t)sgx_get_socket, 0, 0},
		{(void*)(uintptr_t)sgx_get_hms, 0, 0},
		{(void*)(uintptr_t)sgx_compare_enclave_time, 0, 0},
		{(void*)(uintptr_t)sgx_checker, 0, 0},
		{(void*)(uintptr_t)sgx_verifier, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][9];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pass_string(unsigned char* str, int hash_value, int dir_index)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = 633;

	ms_ocall_pass_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pass_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pass_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pass_string_t));
	ocalloc_size -= sizeof(ms_ocall_pass_string_t);

	if (str != NULL) {
		ms->ms_str = (unsigned char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	ms->ms_hash_value = hash_value;
	ms->ms_dir_index = dir_index;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_hex(unsigned char* str, int len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = len;

	ms_ocall_print_hex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_hex_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_hex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_hex_t));
	ocalloc_size -= sizeof(ms_ocall_print_hex_t);

	if (str != NULL) {
		ms->ms_str = (unsigned char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_set_file(char* name, char c1, int num, int num2)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_set_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_set_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_set_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_set_file_t));
	ocalloc_size -= sizeof(ms_ocall_set_file_t);

	if (name != NULL) {
		ms->ms_name = (char*)__tmp;
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}
	
	ms->ms_c1 = c1;
	ms->ms_num = num;
	ms->ms_num2 = num2;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_delete_file(const char* name, char c1, int num)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_delete_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_delete_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_delete_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_delete_file_t));
	ocalloc_size -= sizeof(ms_ocall_delete_file_t);

	if (name != NULL) {
		ms->ms_name = (const char*)__tmp;
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}
	
	ms->ms_c1 = c1;
	ms->ms_num = num;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

