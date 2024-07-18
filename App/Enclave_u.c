#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_t {
	int ms_order;
} ms_ecall_init_t;

typedef struct ms_ecall_search_t {
	int ms_retval;
	int ms_key;
	void* ms_mbdes;
	char** ms_mbpool;
} ms_ecall_search_t;

typedef struct ms_ecall_insert_t {
	void* ms_key_rid;
	void* ms_mbdes;
	char** ms_mbpool;
} ms_ecall_insert_t;

typedef struct ms_ecall_data_search_t {
	char* ms_retval;
	int ms_rid;
	void* ms_mbdes;
	char** ms_mbpool;
} ms_ecall_data_search_t;

typedef struct ms_ecall_data_insert_t {
	char* ms_newdata;
	void* ms_mbdes;
	char** ms_mbpool;
} ms_ecall_data_insert_t;

typedef struct ms_ecall_joinsearch1_t {
	char** ms_ein1;
	char** ms_ein2;
	void* ms_mbdes;
	char** ms_mbpool;
} ms_ecall_joinsearch1_t;

typedef struct ms_ecall_joinsearch2_t {
	char** ms_ein0;
	char** ms_ein1;
	char** ms_ein2;
	char** ms_ein3;
	char** ms_ein4;
	char** ms_ein5;
	char** ms_ein6;
	char** ms_ein7;
	char** ms_ein8;
	char** ms_ein9;
	void* ms_mbdes;
	char** ms_mbpool;
} ms_ecall_joinsearch2_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_readpage_t {
	int ms_page_id;
	char* ms_buffer_field;
} ms_ocall_readpage_t;

typedef struct ms_ocall_writepage_t {
	int ms_page_id;
	char* ms_buffer_field;
} ms_ocall_writepage_t;

typedef struct ms_ocall_sgx_clock_t {
	long int ms_retval;
} ms_ocall_sgx_clock_t;

typedef struct ms_ocall_sgx_time_t {
	time_t ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_time_t;

typedef struct ms_ocall_sgx_localtime_t {
	struct tm* ms_retval;
	const time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_localtime_t;

typedef struct ms_ocall_sgx_gmtime_r_t {
	struct tm* ms_retval;
	const time_t* ms_timep;
	int ms_t_len;
	struct tm* ms_tmp;
	int ms_tmp_len;
} ms_ocall_sgx_gmtime_r_t;

typedef struct ms_ocall_sgx_gettimeofday_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
} ms_ocall_sgx_gettimeofday_t;

typedef struct ms_ocall_sgx_getsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	char* ms_optval;
	int ms_optval_len;
	int* ms_optlen;
} ms_ocall_sgx_getsockopt_t;

typedef struct ms_ocall_sgx_setsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	const void* ms_optval;
	int ms_optlen;
} ms_ocall_sgx_setsockopt_t;

typedef struct ms_ocall_sgx_socket_t {
	int ms_retval;
	int ms_af;
	int ms_type;
	int ms_protocol;
} ms_ocall_sgx_socket_t;

typedef struct ms_ocall_sgx_listen_t {
	int ms_retval;
	int ms_s;
	int ms_backlog;
} ms_ocall_sgx_listen_t;

typedef struct ms_ocall_sgx_bind_t {
	int ms_retval;
	int ms_s;
	const void* ms_addr;
	int ms_addr_size;
} ms_ocall_sgx_bind_t;

typedef struct ms_ocall_sgx_connect_t {
	int ms_retval;
	int ms_s;
	const void* ms_addr;
	int ms_addrlen;
} ms_ocall_sgx_connect_t;

typedef struct ms_ocall_sgx_accept_t {
	int ms_retval;
	int ms_s;
	void* ms_addr;
	int ms_addr_size;
	int* ms_addrlen;
} ms_ocall_sgx_accept_t;

typedef struct ms_ocall_sgx_shutdown_t {
	int ms_retval;
	int ms_fd;
	int ms_how;
} ms_ocall_sgx_shutdown_t;

typedef struct ms_ocall_sgx_read_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	int ms_n;
} ms_ocall_sgx_read_t;

typedef struct ms_ocall_sgx_write_t {
	int ms_retval;
	int ms_fd;
	const void* ms_buf;
	int ms_n;
} ms_ocall_sgx_write_t;

typedef struct ms_ocall_sgx_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_sgx_close_t;

typedef struct ms_ocall_sgx_getenv_t {
	int ms_retval;
	const char* ms_env;
	int ms_envlen;
	char* ms_ret_str;
	int ms_ret_len;
} ms_ocall_sgx_getenv_t;

typedef struct ms_ocall_read_eneq0_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq0_t;

typedef struct ms_ocall_read_eneq1_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq1_t;

typedef struct ms_ocall_read_eneq2_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq2_t;

typedef struct ms_ocall_read_eneq3_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq3_t;

typedef struct ms_ocall_read_eneq4_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq4_t;

typedef struct ms_ocall_read_eneq5_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq5_t;

typedef struct ms_ocall_read_eneq6_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq6_t;

typedef struct ms_ocall_read_eneq7_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq7_t;

typedef struct ms_ocall_read_eneq8_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq8_t;

typedef struct ms_ocall_read_eneq9_t {
	int ms_retval;
	char** ms_eneq;
} ms_ocall_read_eneq9_t;

typedef struct ms_ocall_write_result_t {
	int ms_data;
} ms_ocall_write_result_t;

typedef struct ms_ocall_read_s_t {
	char* ms_s;
	int ms_n;
} ms_ocall_read_s_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readpage(void* pms)
{
	ms_ocall_readpage_t* ms = SGX_CAST(ms_ocall_readpage_t*, pms);
	ocall_readpage(ms->ms_page_id, ms->ms_buffer_field);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writepage(void* pms)
{
	ms_ocall_writepage_t* ms = SGX_CAST(ms_ocall_writepage_t*, pms);
	ocall_writepage(ms->ms_page_id, ms->ms_buffer_field);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_clock(void* pms)
{
	ms_ocall_sgx_clock_t* ms = SGX_CAST(ms_ocall_sgx_clock_t*, pms);
	ms->ms_retval = ocall_sgx_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_time(void* pms)
{
	ms_ocall_sgx_time_t* ms = SGX_CAST(ms_ocall_sgx_time_t*, pms);
	ms->ms_retval = ocall_sgx_time(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_localtime(void* pms)
{
	ms_ocall_sgx_localtime_t* ms = SGX_CAST(ms_ocall_sgx_localtime_t*, pms);
	ms->ms_retval = ocall_sgx_localtime(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gmtime_r(void* pms)
{
	ms_ocall_sgx_gmtime_r_t* ms = SGX_CAST(ms_ocall_sgx_gmtime_r_t*, pms);
	ms->ms_retval = ocall_sgx_gmtime_r(ms->ms_timep, ms->ms_t_len, ms->ms_tmp, ms->ms_tmp_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gettimeofday(void* pms)
{
	ms_ocall_sgx_gettimeofday_t* ms = SGX_CAST(ms_ocall_sgx_gettimeofday_t*, pms);
	ms->ms_retval = ocall_sgx_gettimeofday(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getsockopt(void* pms)
{
	ms_ocall_sgx_getsockopt_t* ms = SGX_CAST(ms_ocall_sgx_getsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_getsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optval_len, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setsockopt(void* pms)
{
	ms_ocall_sgx_setsockopt_t* ms = SGX_CAST(ms_ocall_sgx_setsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_setsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_socket(void* pms)
{
	ms_ocall_sgx_socket_t* ms = SGX_CAST(ms_ocall_sgx_socket_t*, pms);
	ms->ms_retval = ocall_sgx_socket(ms->ms_af, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_listen(void* pms)
{
	ms_ocall_sgx_listen_t* ms = SGX_CAST(ms_ocall_sgx_listen_t*, pms);
	ms->ms_retval = ocall_sgx_listen(ms->ms_s, ms->ms_backlog);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_bind(void* pms)
{
	ms_ocall_sgx_bind_t* ms = SGX_CAST(ms_ocall_sgx_bind_t*, pms);
	ms->ms_retval = ocall_sgx_bind(ms->ms_s, ms->ms_addr, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_connect(void* pms)
{
	ms_ocall_sgx_connect_t* ms = SGX_CAST(ms_ocall_sgx_connect_t*, pms);
	ms->ms_retval = ocall_sgx_connect(ms->ms_s, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_accept(void* pms)
{
	ms_ocall_sgx_accept_t* ms = SGX_CAST(ms_ocall_sgx_accept_t*, pms);
	ms->ms_retval = ocall_sgx_accept(ms->ms_s, ms->ms_addr, ms->ms_addr_size, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_shutdown(void* pms)
{
	ms_ocall_sgx_shutdown_t* ms = SGX_CAST(ms_ocall_sgx_shutdown_t*, pms);
	ms->ms_retval = ocall_sgx_shutdown(ms->ms_fd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_read(void* pms)
{
	ms_ocall_sgx_read_t* ms = SGX_CAST(ms_ocall_sgx_read_t*, pms);
	ms->ms_retval = ocall_sgx_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_write(void* pms)
{
	ms_ocall_sgx_write_t* ms = SGX_CAST(ms_ocall_sgx_write_t*, pms);
	ms->ms_retval = ocall_sgx_write(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_close(void* pms)
{
	ms_ocall_sgx_close_t* ms = SGX_CAST(ms_ocall_sgx_close_t*, pms);
	ms->ms_retval = ocall_sgx_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getenv(void* pms)
{
	ms_ocall_sgx_getenv_t* ms = SGX_CAST(ms_ocall_sgx_getenv_t*, pms);
	ms->ms_retval = ocall_sgx_getenv(ms->ms_env, ms->ms_envlen, ms->ms_ret_str, ms->ms_ret_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq0(void* pms)
{
	ms_ocall_read_eneq0_t* ms = SGX_CAST(ms_ocall_read_eneq0_t*, pms);
	ms->ms_retval = ocall_read_eneq0(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq1(void* pms)
{
	ms_ocall_read_eneq1_t* ms = SGX_CAST(ms_ocall_read_eneq1_t*, pms);
	ms->ms_retval = ocall_read_eneq1(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq2(void* pms)
{
	ms_ocall_read_eneq2_t* ms = SGX_CAST(ms_ocall_read_eneq2_t*, pms);
	ms->ms_retval = ocall_read_eneq2(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq3(void* pms)
{
	ms_ocall_read_eneq3_t* ms = SGX_CAST(ms_ocall_read_eneq3_t*, pms);
	ms->ms_retval = ocall_read_eneq3(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq4(void* pms)
{
	ms_ocall_read_eneq4_t* ms = SGX_CAST(ms_ocall_read_eneq4_t*, pms);
	ms->ms_retval = ocall_read_eneq4(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq5(void* pms)
{
	ms_ocall_read_eneq5_t* ms = SGX_CAST(ms_ocall_read_eneq5_t*, pms);
	ms->ms_retval = ocall_read_eneq5(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq6(void* pms)
{
	ms_ocall_read_eneq6_t* ms = SGX_CAST(ms_ocall_read_eneq6_t*, pms);
	ms->ms_retval = ocall_read_eneq6(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq7(void* pms)
{
	ms_ocall_read_eneq7_t* ms = SGX_CAST(ms_ocall_read_eneq7_t*, pms);
	ms->ms_retval = ocall_read_eneq7(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq8(void* pms)
{
	ms_ocall_read_eneq8_t* ms = SGX_CAST(ms_ocall_read_eneq8_t*, pms);
	ms->ms_retval = ocall_read_eneq8(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_eneq9(void* pms)
{
	ms_ocall_read_eneq9_t* ms = SGX_CAST(ms_ocall_read_eneq9_t*, pms);
	ms->ms_retval = ocall_read_eneq9(ms->ms_eneq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open_result(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_open_result();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_result(void* pms)
{
	ms_ocall_write_result_t* ms = SGX_CAST(ms_ocall_write_result_t*, pms);
	ocall_write_result(ms->ms_data);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writeendl_result(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_writeendl_result();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close_result(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_close_result();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open_enquery(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_open_enquery();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_s(void* pms)
{
	ms_ocall_read_s_t* ms = SGX_CAST(ms_ocall_read_s_t*, pms);
	ocall_read_s(ms->ms_s, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close_enquery(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_close_enquery();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[42];
} ocall_table_Enclave = {
	42,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_readpage,
		(void*)Enclave_ocall_writepage,
		(void*)Enclave_ocall_sgx_clock,
		(void*)Enclave_ocall_sgx_time,
		(void*)Enclave_ocall_sgx_localtime,
		(void*)Enclave_ocall_sgx_gmtime_r,
		(void*)Enclave_ocall_sgx_gettimeofday,
		(void*)Enclave_ocall_sgx_getsockopt,
		(void*)Enclave_ocall_sgx_setsockopt,
		(void*)Enclave_ocall_sgx_socket,
		(void*)Enclave_ocall_sgx_listen,
		(void*)Enclave_ocall_sgx_bind,
		(void*)Enclave_ocall_sgx_connect,
		(void*)Enclave_ocall_sgx_accept,
		(void*)Enclave_ocall_sgx_shutdown,
		(void*)Enclave_ocall_sgx_read,
		(void*)Enclave_ocall_sgx_write,
		(void*)Enclave_ocall_sgx_close,
		(void*)Enclave_ocall_sgx_getenv,
		(void*)Enclave_ocall_read_eneq0,
		(void*)Enclave_ocall_read_eneq1,
		(void*)Enclave_ocall_read_eneq2,
		(void*)Enclave_ocall_read_eneq3,
		(void*)Enclave_ocall_read_eneq4,
		(void*)Enclave_ocall_read_eneq5,
		(void*)Enclave_ocall_read_eneq6,
		(void*)Enclave_ocall_read_eneq7,
		(void*)Enclave_ocall_read_eneq8,
		(void*)Enclave_ocall_read_eneq9,
		(void*)Enclave_ocall_open_result,
		(void*)Enclave_ocall_write_result,
		(void*)Enclave_ocall_writeendl_result,
		(void*)Enclave_ocall_close_result,
		(void*)Enclave_ocall_open_enquery,
		(void*)Enclave_ocall_read_s,
		(void*)Enclave_ocall_close_enquery,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid, int order)
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	ms.ms_order = order;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_search(sgx_enclave_id_t eid, int* retval, int key, void* mbdes, char** mbpool)
{
	sgx_status_t status;
	ms_ecall_search_t ms;
	ms.ms_key = key;
	ms.ms_mbdes = mbdes;
	ms.ms_mbpool = mbpool;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_insert(sgx_enclave_id_t eid, void* key_rid, void* mbdes, char** mbpool)
{
	sgx_status_t status;
	ms_ecall_insert_t ms;
	ms.ms_key_rid = key_rid;
	ms.ms_mbdes = mbdes;
	ms.ms_mbpool = mbpool;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_traversal(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_data_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_data_search(sgx_enclave_id_t eid, char** retval, int rid, void* mbdes, char** mbpool)
{
	sgx_status_t status;
	ms_ecall_data_search_t ms;
	ms.ms_rid = rid;
	ms.ms_mbdes = mbdes;
	ms.ms_mbpool = mbpool;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_data_insert(sgx_enclave_id_t eid, char* newdata, void* mbdes, char** mbpool)
{
	sgx_status_t status;
	ms_ecall_data_insert_t ms;
	ms.ms_newdata = newdata;
	ms.ms_mbdes = mbdes;
	ms.ms_mbpool = mbpool;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_joinsearch1(sgx_enclave_id_t eid, char** ein1, char** ein2, void* mbdes, char** mbpool)
{
	sgx_status_t status;
	ms_ecall_joinsearch1_t ms;
	ms.ms_ein1 = ein1;
	ms.ms_ein2 = ein2;
	ms.ms_mbdes = mbdes;
	ms.ms_mbpool = mbpool;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_joinsearch2(sgx_enclave_id_t eid, char** ein0, char** ein1, char** ein2, char** ein3, char** ein4, char** ein5, char** ein6, char** ein7, char** ein8, char** ein9, void* mbdes, char** mbpool)
{
	sgx_status_t status;
	ms_ecall_joinsearch2_t ms;
	ms.ms_ein0 = ein0;
	ms.ms_ein1 = ein1;
	ms.ms_ein2 = ein2;
	ms.ms_ein3 = ein3;
	ms.ms_ein4 = ein4;
	ms.ms_ein5 = ein5;
	ms.ms_ein6 = ein6;
	ms.ms_ein7 = ein7;
	ms.ms_ein8 = ein8;
	ms.ms_ein9 = ein9;
	ms.ms_mbdes = mbdes;
	ms.ms_mbpool = mbpool;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

