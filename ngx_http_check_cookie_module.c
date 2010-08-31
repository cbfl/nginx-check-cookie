/*
 * (C) 2009
 * Usage:
	check_cookie "cookie_name" "secret_key/password" "x-header" "timeout_in_sec" $cookie_result_var;
	if ($cookie_result_var ~ ^$) {
		NOT_AUTHORIZED
	}

	* Cookie format:
		BASE64_ENCODE( MD5( SECRET_KEY - TIMESTAMP - USERID) - TIMESTAMP - USERID - REMOTE_ADDR )
*/
#include <ngx_config.h>
#include <ngx_core.h> 
#include <ngx_http.h>

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init	MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

typedef struct {
	ngx_str_t	 name;
	ngx_str_t	 password;
	ngx_str_t	 x_header;
	ngx_str_t	 x_header_token;
	ngx_int_t	 timeout;
} ngx_http_check_cookie_conf_t;

/* Variable handlers */
static char *ngx_http_check_cookie_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_check_cookie_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_command_t ngx_http_check_cookie_commands[] = {
	{
		ngx_string("check_cookie"),
		NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE5,
		ngx_http_check_cookie_init,
		0,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_check_cookie_module_ctx = {
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_check_cookie_module = {
	NGX_MODULE_V1,
	&ngx_http_check_cookie_module_ctx, /* module context */
	ngx_http_check_cookie_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	NULL, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	NULL, /* exit master */
	NGX_MODULE_V1_PADDING
};

static char * ngx_http_check_cookie_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *check_cookie_vars;
	ngx_http_variable_t *vMD5Variable;
	check_cookie_vars = cf->args->elts;

	/* TODO some more validations & checks */
	if (check_cookie_vars[5].data[0] != '$') {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: invalid parameter: \"%s\"", check_cookie_vars[5].data);
		return NGX_CONF_ERROR;
	}
	check_cookie_vars[5].len--;
	check_cookie_vars[5].data++;
	vMD5Variable = ngx_http_add_variable(cf, &check_cookie_vars[5], NGX_HTTP_VAR_CHANGEABLE);
	if (vMD5Variable == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: cannot add variable: \"%s\"", check_cookie_vars[5].data);
		return NGX_CONF_ERROR;
	}
	if (vMD5Variable->get_handler == NULL ) {
		vMD5Variable->get_handler = ngx_http_check_cookie_variable;
 
		ngx_http_check_cookie_conf_t  *check_cookie_conf;
		check_cookie_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_check_cookie_conf_t));
		if (check_cookie_conf == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: allocation failed");
			return NGX_CONF_ERROR;
		}

		check_cookie_conf->name.len = check_cookie_vars[1].len;
		check_cookie_conf->name.data = ngx_palloc(cf->pool, check_cookie_vars[1].len + 1);
		if (check_cookie_conf->name.data == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: allocation failed");
			return NGX_CONF_ERROR;
		}
		ngx_cpystrn(check_cookie_conf->name.data, check_cookie_vars[1].data, check_cookie_vars[1].len + 1);
		
		check_cookie_conf->password.len = check_cookie_vars[2].len;
		check_cookie_conf->password.data = ngx_palloc(cf->pool, check_cookie_vars[2].len + 1);
		if (check_cookie_conf->password.data == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: allocation failed");
			return NGX_CONF_ERROR;
		}
		ngx_cpystrn(check_cookie_conf->password.data, check_cookie_vars[2].data, check_cookie_vars[2].len + 1);
		
		check_cookie_conf->x_header.len = check_cookie_vars[3].len;
		check_cookie_conf->x_header.data = ngx_palloc(cf->pool, check_cookie_vars[3].len + 1);
		if (check_cookie_conf->x_header.data == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: allocation failed");
			return NGX_CONF_ERROR;
		}
		ngx_cpystrn(check_cookie_conf->x_header.data, check_cookie_vars[3].data, check_cookie_vars[3].len + 1);
		
		check_cookie_conf->timeout = ngx_atoi(check_cookie_vars[4].data, check_cookie_vars[4].len);
		if (check_cookie_conf->timeout == NGX_ERROR || check_cookie_conf->timeout < 0) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_cookie_module: invalid timeout - must be integer >= 0");
			return NGX_CONF_ERROR;
		}
		vMD5Variable->data = (uintptr_t) check_cookie_conf;
	}
	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_check_cookie_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http_check_cookie_conf_t  *check_cookie_conf = (ngx_http_check_cookie_conf_t *) data;

	/* Reset variable */
	v->valid = 0;
	v->not_found = 1;
	if (check_cookie_conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: runtime error \"data\" is NULL");
		return NGX_OK;
	}

	/* Check Cookie */
	ngx_str_t base64_encoded_cookie;
	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &check_cookie_conf->name, &base64_encoded_cookie) == NGX_DECLINED) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: cookie \"%V\" not found", &check_cookie_conf->name);
		return NGX_OK;
	}

	/* Unescape cookie */
	u_char *dst_base64_encoded_cookie, *src_base64_encoded_cookie;
	size_t unescape_len;
	dst_base64_encoded_cookie = base64_encoded_cookie.data;
	src_base64_encoded_cookie = base64_encoded_cookie.data;
	ngx_unescape_uri(&dst_base64_encoded_cookie, &src_base64_encoded_cookie, base64_encoded_cookie.len,  NGX_UNESCAPE_URI);
	unescape_len = (base64_encoded_cookie.data + base64_encoded_cookie.len) - src_base64_encoded_cookie;
	if (unescape_len) {
		dst_base64_encoded_cookie = ngx_copy(dst_base64_encoded_cookie, src_base64_encoded_cookie, unescape_len);
	}
	base64_encoded_cookie.len = dst_base64_encoded_cookie - base64_encoded_cookie.data;
	base64_encoded_cookie.data[base64_encoded_cookie.len] = '\0';

	/* Base64 decode cookie */
	ngx_str_t cookie;
	cookie.len = ngx_base64_decoded_length(base64_encoded_cookie.len);
	cookie.data = ngx_pnalloc(r->pool, cookie.len + 1);
	if (cookie.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cook	ie_module: allocation failed");
		return NGX_OK;
	}
	if (ngx_decode_base64(&cookie, &base64_encoded_cookie) == NGX_ERROR) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: invalid base64 encoded cookie");
		return NGX_OK;
	}
	cookie.data[cookie.len] = '\0';

	if (cookie.len <  (32 + 1 + 10 + 1 + 1)) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: invalid cookie length: %i", cookie.len);
		return NGX_OK;
	}
	if (cookie.data[32] != '-' || cookie.data[43] != '-') {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: invalid cookie format: \"%s\"", cookie.data);
		return NGX_OK;
	}
	

	/* Check Time/Timeout */
	ngx_str_t cookie_time_text = ngx_string("");
	cookie_time_text.len = 10; //Timestamp
	cookie_time_text.data = ngx_pnalloc(r->pool, cookie_time_text.len + 1);
	if (cookie_time_text.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: allocation failed");
		return NGX_OK;
	}

	ngx_cpystrn(cookie_time_text.data, cookie.data + 32 + 1, cookie_time_text.len + 1);
	cookie_time_text.data[cookie_time_text.len] = '\0';
	time_t cookie_time = ngx_atotm(cookie_time_text.data, cookie_time_text.len);
	if (cookie_time == NGX_ERROR) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: invalid timestamp in cookie");
		return NGX_OK;
	}
	time_t local_time = time(NULL);
	if (local_time - cookie_time > check_cookie_conf->timeout) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: Expired %i", local_time - cookie_time);
		return NGX_OK;
	}

	/* Find last "-" in cookie */
	size_t  cookie_uid_end = 0;
	for(cookie_uid_end = cookie.len - 1; cookie_uid_end > 0  ; cookie_uid_end--){
		if (cookie.data[cookie_uid_end] == '-') {
			break;
		}
	}
	if (cookie_uid_end < (32 + 1 + cookie_time_text.len + 1)) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: invalid uid in cookie");
		return NGX_OK;
	}

	/* UID */
	ngx_str_t cookie_uid_text = ngx_string("");
	cookie_uid_text.len = cookie_uid_end - (32 + 1 + cookie_time_text.len + 1);
	cookie_uid_text.data = ngx_pnalloc(r->pool, cookie_uid_text.len + 1);
	if (cookie_uid_text.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: allocation failed");
		return NGX_OK;
	}
	ngx_cpystrn(cookie_uid_text.data, cookie.data + (32 + 1 + cookie_time_text.len + 1), cookie_uid_text.len + 1);
	cookie_uid_text.data[cookie_uid_text.len] = '\0';

	// /* IP */
	// ngx_str_t client_ip_addr = ngx_string("");
	// 
	// /* check for trusted proxy */
	// ngx_list_part_t *part;
	// ngx_table_elt_t *header;
	// ngx_uint_t j;
	// part = &r->headers_in.headers.part;
	// header = part->elts;
	// for (j = 0; /* void */; j++) {
	// 	if (j >= part->nelts) {
	// 		if (part->next == NULL) break;
	// 		part = part->next;
	// 		header = part->elts;
	// 		j = 0;
	// 	}
	// 	if (ngx_strncmp(header[j].key.data, check_cookie_conf->x_header.data, check_cookie_conf->x_header.len) == 0) {
	// 		client_ip_addr.data = ngx_pnalloc(r->pool, header[j].value.len + 1);
	// 		if (client_ip_addr.data == NULL) {
	// 			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: allocation failed");
	// 			return NGX_OK;
	// 		}
	// 		ngx_cpystrn(client_ip_addr.data, header[j].value.data, header[j].value.len + 1);
	// 		client_ip_addr.len = header[j].value.len;
	// 		client_ip_addr.data[client_ip_addr.len] = '\0';
	// 		break;
	// 	}
	// }
	// if(client_ip_addr.len == 0){
	// 	client_ip_addr.data = ngx_pnalloc(r->pool, r->connection->addr_text.len + 1);
	// 	if (client_ip_addr.data == NULL) {
	// 		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: allocation failed");
	// 		return NGX_OK;
	// 	}
	// 	ngx_cpystrn(client_ip_addr.data, r->connection->addr_text.data, r->connection->addr_text.len + 1);
	// 	client_ip_addr.len = r->connection->addr_text.len;
	// 	client_ip_addr.data[client_ip_addr.len] = '\0';
	// }
	// 
	// /* Remove last octet from ip  */
	// ngx_int_t  ip_i;
	// for(ip_i = client_ip_addr.len - 1; ip_i > 0  ; ip_i--){
	// 	if (client_ip_addr.data[ip_i] == '.') {
	// 		client_ip_addr.len = ip_i;
	// 		break;
	// 	}
	// }
	// client_ip_addr.data[client_ip_addr.len] = '\0';

	/* Create MD5 signature */
	
	ngx_str_t raw_data = ngx_string("");
	raw_data.len = check_cookie_conf->password.len + 1 + cookie_time_text.len + 1 + cookie_uid_text.len;
	raw_data.data = ngx_pnalloc(r->pool, raw_data.len + 1);
	if (raw_data.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: allocation failed");
		return NGX_OK;
	}
	ngx_snprintf(raw_data.data, raw_data.len, "%s-%s-%s", check_cookie_conf->password.data, cookie_time_text.data, cookie_uid_text.data);
	raw_data.data[raw_data.len] = '\0';
	
/*
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: client_ip_addr.data: %s",client_ip_addr.data);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: client_ip_addr.len: %i",client_ip_addr.len);

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: cookie_time_text.data: %s",cookie_time_text.data);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: cookie_time_text.len: %i",cookie_time_text.len);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: cookie_uid_text.data: %s",cookie_uid_text.data);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: cookie_uid_text.len: %i",cookie_uid_text.len);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: raw_data.data: %s",raw_data.data);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "DEBUG: raw_data.len: %i",raw_data.len);
*/
	/* MD5 */
	u_char hash_bin[64], hash_txt[128];
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, raw_data.data, raw_data.len);
	MD5Final(hash_bin, &md5);
	static u_char hex[] = "0123456789abcdef";
	u_char *text = hash_txt;
	ngx_int_t i;
	for (i = 0; i < 16; i++) {
		*text++ = hex[hash_bin[i] >> 4];
		*text++ = hex[hash_bin[i] & 0xf];
	}
	*text = '\0';

	if (ngx_strncmp(hash_txt, cookie.data, 32) != 0) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: MD5 dont match: %s <> %s", hash_txt, cookie.data);
		return NGX_OK;
	}

	v->data = (u_char *) hash_txt;
	v->len = ngx_strlen( v->data );
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_cookie_module: Authorized OK - %s, MD5: %s", raw_data.data, hash_txt);
	return NGX_OK;
}
