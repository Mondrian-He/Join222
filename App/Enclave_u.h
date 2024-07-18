#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "user_types.h"
#include "time.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_READPAGE_DEFINED__
#define OCALL_READPAGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readpage, (int page_id, char* buffer_field));
#endif
#ifndef OCALL_WRITEPAGE_DEFINED__
#define OCALL_WRITEPAGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writepage, (int page_id, char* buffer_field));
#endif
#ifndef OCALL_SGX_CLOCK_DEFINED__
#define OCALL_SGX_CLOCK_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock, (void));
#endif
#ifndef OCALL_SGX_TIME_DEFINED__
#define OCALL_SGX_TIME_DEFINED__
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_time, (time_t* timep, int t_len));
#endif
#ifndef OCALL_SGX_LOCALTIME_DEFINED__
#define OCALL_SGX_LOCALTIME_DEFINED__
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_localtime, (const time_t* timep, int t_len));
#endif
#ifndef OCALL_SGX_GMTIME_R_DEFINED__
#define OCALL_SGX_GMTIME_R_DEFINED__
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gmtime_r, (const time_t* timep, int t_len, struct tm* tmp, int tmp_len));
#endif
#ifndef OCALL_SGX_GETTIMEOFDAY_DEFINED__
#define OCALL_SGX_GETTIMEOFDAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gettimeofday, (void* tv, int tv_size));
#endif
#ifndef OCALL_SGX_GETSOCKOPT_DEFINED__
#define OCALL_SGX_GETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockopt, (int s, int level, int optname, char* optval, int optval_len, int* optlen));
#endif
#ifndef OCALL_SGX_SETSOCKOPT_DEFINED__
#define OCALL_SGX_SETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsockopt, (int s, int level, int optname, const void* optval, int optlen));
#endif
#ifndef OCALL_SGX_SOCKET_DEFINED__
#define OCALL_SGX_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socket, (int af, int type, int protocol));
#endif
#ifndef OCALL_SGX_LISTEN_DEFINED__
#define OCALL_SGX_LISTEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_listen, (int s, int backlog));
#endif
#ifndef OCALL_SGX_BIND_DEFINED__
#define OCALL_SGX_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_bind, (int s, const void* addr, int addr_size));
#endif
#ifndef OCALL_SGX_CONNECT_DEFINED__
#define OCALL_SGX_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_connect, (int s, const void* addr, int addrlen));
#endif
#ifndef OCALL_SGX_ACCEPT_DEFINED__
#define OCALL_SGX_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_accept, (int s, void* addr, int addr_size, int* addrlen));
#endif
#ifndef OCALL_SGX_SHUTDOWN_DEFINED__
#define OCALL_SGX_SHUTDOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_shutdown, (int fd, int how));
#endif
#ifndef OCALL_SGX_READ_DEFINED__
#define OCALL_SGX_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_read, (int fd, void* buf, int n));
#endif
#ifndef OCALL_SGX_WRITE_DEFINED__
#define OCALL_SGX_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_write, (int fd, const void* buf, int n));
#endif
#ifndef OCALL_SGX_CLOSE_DEFINED__
#define OCALL_SGX_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_close, (int fd));
#endif
#ifndef OCALL_SGX_GETENV_DEFINED__
#define OCALL_SGX_GETENV_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getenv, (const char* env, int envlen, char* ret_str, int ret_len));
#endif
#ifndef OCALL_READ_ENEQ0_DEFINED__
#define OCALL_READ_ENEQ0_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq0, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ1_DEFINED__
#define OCALL_READ_ENEQ1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq1, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ2_DEFINED__
#define OCALL_READ_ENEQ2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq2, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ3_DEFINED__
#define OCALL_READ_ENEQ3_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq3, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ4_DEFINED__
#define OCALL_READ_ENEQ4_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq4, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ5_DEFINED__
#define OCALL_READ_ENEQ5_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq5, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ6_DEFINED__
#define OCALL_READ_ENEQ6_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq6, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ7_DEFINED__
#define OCALL_READ_ENEQ7_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq7, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ8_DEFINED__
#define OCALL_READ_ENEQ8_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq8, (char** eneq));
#endif
#ifndef OCALL_READ_ENEQ9_DEFINED__
#define OCALL_READ_ENEQ9_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_eneq9, (char** eneq));
#endif
#ifndef OCALL_OPEN_RESULT_DEFINED__
#define OCALL_OPEN_RESULT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open_result, (void));
#endif
#ifndef OCALL_WRITE_RESULT_DEFINED__
#define OCALL_WRITE_RESULT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_result, (int data));
#endif
#ifndef OCALL_WRITEENDL_RESULT_DEFINED__
#define OCALL_WRITEENDL_RESULT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writeendl_result, (void));
#endif
#ifndef OCALL_CLOSE_RESULT_DEFINED__
#define OCALL_CLOSE_RESULT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close_result, (void));
#endif
#ifndef OCALL_OPEN_ENQUERY_DEFINED__
#define OCALL_OPEN_ENQUERY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open_enquery, (void));
#endif
#ifndef OCALL_READ_S_DEFINED__
#define OCALL_READ_S_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_s, (char* s, int n));
#endif
#ifndef OCALL_CLOSE_ENQUERY_DEFINED__
#define OCALL_CLOSE_ENQUERY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close_enquery, (void));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid, int order);
sgx_status_t ecall_search(sgx_enclave_id_t eid, int* retval, int key, void* mbdes, char** mbpool);
sgx_status_t ecall_insert(sgx_enclave_id_t eid, void* key_rid, void* mbdes, char** mbpool);
sgx_status_t ecall_traversal(sgx_enclave_id_t eid);
sgx_status_t ecall_data_init(sgx_enclave_id_t eid);
sgx_status_t ecall_data_search(sgx_enclave_id_t eid, char** retval, int rid, void* mbdes, char** mbpool);
sgx_status_t ecall_data_insert(sgx_enclave_id_t eid, char* newdata, void* mbdes, char** mbpool);
sgx_status_t ecall_joinsearch1(sgx_enclave_id_t eid, char** ein1, char** ein2, void* mbdes, char** mbpool);
sgx_status_t ecall_joinsearch2(sgx_enclave_id_t eid, char** ein0, char** ein1, char** ein2, char** ein3, char** ein4, char** ein5, char** ein6, char** ein7, char** ein8, char** ein9, void* mbdes, char** mbpool);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
