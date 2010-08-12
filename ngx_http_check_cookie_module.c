/*
 * (C) 2009
 * Usage:
	check_cookie "cookie_name" "secret_key/password" "x-header" "timeout_in_sec" $cookie_result_var;
	if ($cookie_result_var ~ ^$) {
		NOT_AUTHORIZED
	}

	* Cookie format:
		BASE64_ENCODE( MD5( REOMOTE_ADDR - SECRET_KEY - TIMESTAMP - USERID) - TIMESTAMP - USERID )
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
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: cookie \"%V\" not found", &check_cookie_conf->name);
		return NGX_OK;
	}

	/* Base64 decode cookie */
	ngx_str_t cookie;
	cookie.len = ngx_base64_decoded_length(base64_encoded_cookie.len);
	cookie.data = ngx_pnalloc(r->pool, cookie.len + 1);
	if (cookie.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cook	ie_module: allocation failed");
		return NGX_OK;
	}
	if (ngx_decode_base64(&cookie, &base64_encoded_cookie) == NGX_ERROR) {
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: invalid base64 encoded cookie");
		return NGX_OK;
	}
	cookie.data[cookie.len] = '\0';

	if (cookie.len <  (32 + 1 + 10 + 1 + 1)) {
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: invalid cookie length: %i", cookie.len);
		return NGX_OK;
	}
	if (cookie.data[32] != '-' || cookie.data[43] != '-') {
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: invalid cookie format: \"%s\"", cookie.data);
		return NGX_OK;
	}

	/* unescape cookie value */
	/*
	u_char *dst_cookie_data, *src_cookie_data;
	size_t len;
	dst_cookie_data = cookie.data;
	src_cookie_data = cookie.data;
	ngx_unescape_uri(&dst_cookie_data, &src_cookie_data, cookie.len,  NGX_UNESCAPE_URI);
	len = (cookie.data + cookie.len) - src_cookie_data;
	if (len) {
		dst_cookie_data = ngx_copy(dst_cookie_data, src_cookie_data, len);
	}
	cookie.len = dst_cookie_data - cookie.data;
	cookie.data[cookie.len] = '\0';
	*/

	/* Check Time/Timeout */
	u_char* cookie_time_text = cookie.data + (32 + 1);
	time_t cookie_time = ngx_atotm(cookie_time_text, 10);
	if (cookie_time == NGX_ERROR) {
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: invalid timestamp in cookie");
		return NGX_OK;
	}
	time_t local_time = time(NULL);

	if (local_time - cookie_time > check_cookie_conf->timeout) {
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: Expired %i", local_time - cookie_time);
		return NGX_OK;
	}

	/* UID */
	u_char* cookie_uid_text = cookie.data + (32 + 1 + 10 + 1);
	/* ngx_int_t cookie_uid = ngx_atoi(cookie_uid_text, cookie.len - (32 + 1 + 10 + 1)); */

	/* IP */
	ngx_str_t remote_addr = ngx_string("");

	/* check for trusted proxy */
	ngx_list_part_t *part;
	ngx_table_elt_t *header;
	ngx_uint_t j;
	part = &r->headers_in.headers.part;
	header = part->elts;
	for (j = 0; /* void */; j++) {
		if (j >= part->nelts) {
			if (part->next == NULL) break;
			part = part->next;
			header = part->elts;
			j = 0;
		}
		if (ngx_strncmp(header[j].key.data, check_cookie_conf->x_header.data, check_cookie_conf->x_header.len) == 0) {
			remote_addr = header[j].value;
			break;
		}
	}
	if(remote_addr.len == 0)  remote_addr = r->connection->addr_text;
	remote_addr.data[remote_addr.len] = '\0';
	
	/* Remove last octet from ip  */
	ngx_int_t  ip_i;
	for(ip_i = remote_addr.len - 1; ip_i > 0  ; ip_i--){
		if (remote_addr.data[ip_i] == '.') {
			remote_addr.len = ip_i;
			break;
		}
	}
	remote_addr.data[remote_addr.len] = '\0';

	/* Create MD5 signature */
	size_t raw_data_len = remote_addr.len + 1 + check_cookie_conf->password.len + 1 + 10 + 1 + (cookie.len - (32 + 1 + 10 + 1)) + 1;
	u_char* raw_data = ngx_palloc(r->pool, raw_data_len);
	if (raw_data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_cookie_module: allocation error - raw_data");
		return NGX_OK;
	}

	ngx_snprintf(raw_data, raw_data_len, "%s-%s-%T-%s", remote_addr.data, check_cookie_conf->password.data, cookie_time, cookie_uid_text);
	raw_data[raw_data_len] = '\0';

	/* MD5 */
	u_char hash_bin[64], hash_txt[128];
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, raw_data, raw_data_len - 1);
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
		ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: MD5 dont match: %s <> %s", hash_txt, cookie.data);
		return NGX_OK;
	}

	v->data = (u_char *) hash_txt;
	v->len = ngx_strlen( v->data );
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "check_cookie_module: Authorized OK - %s, MD5: %s", raw_data, hash_txt);
	return NGX_OK;
}
