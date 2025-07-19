#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#include "buff.h"
#include "http_parser.h"
#include "ssl.h"
#include "server.h"
#include "utils.h"

#if (SSL_ENABLED)

int ssl_init(struct server_t *srv, const char *cert, const char *key)
{
	SSL_CTX *ctx = NULL;

	SSL_library_init();

	/* registers the error strings for all libssl functions */
	SSL_load_error_strings();
	
	/* creates a new SSL_CTX object */
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		log_e("Failed to create SSL context");
		return -1;
	}

	/* loads the first certificate stored in file into ctx */
	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
		log_e("OpenSSL Error: loading certificate file failed");
		goto err;
	}
		
	/*
	 * adds the first private RSA key found in file to ctx.
	 *
	 * checks the consistency of a private key with the corresponding 
	 * certificate loaded into ctx. If more than one key/certificate 
	 * pair (RSA/DSA) is installed, the last item installed will be checked.
	 */
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
		log_e("OpenSSL Error: loading key failed");
		goto err;
	}
	srv->ssl_ctx = ctx;
	return 0;
	
err:
	SSL_CTX_free(ctx);
	return -1;
}
#endif

void ssl_ctx_free(struct server_t *srv)
{
#if (SSL_ENABLED)
	if (!srv->ssl_ctx)
		return;
	SSL_CTX_free(srv->ssl_ctx);
#endif
}

void ssl_free(struct connection *con)
{
#if (SSL_ENABLED)
	if (!con->ssl)
		return;
	SSL_shutdown(con->ssl);
	SSL_free(con->ssl);
#endif
}

#if (SSL_ENABLED)
static int ssl_err(struct connection *con, int ret, const char *fun)
{
	int err;
	err = SSL_get_error(con->ssl, ret);
	if (err == SSL_ERROR_ZERO_RETURN || ERR_peek_error()) {
		con->flags |= CNN_CLOSE;
		return 0;
	}
	
#if (USE_OPENSSL)
	if (ret == 0) {
		con->flags |= CNN_CLOSE;
		return 0;
	}
#endif

	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		return -1;

	if (err == SSL_ERROR_SYSCALL) {
		if (errno > 0)
			log_e("%s", fun);
		con->flags |= CNN_CLOSE;
		return -1;
	}

	con->flags |= CNN_CLOSE;
	log_e("%s() Error: %s", fun, ERR_reason_error_string(err));
	
	return -1;
}
#endif

int ssl_read(struct connection *con, void *buf, int count)
{
	int ret = -1;
#if (SSL_ENABLED)
	if (!con->ssl)
		goto no_ssl;

	ret = SSL_read(con->ssl, buf, count);
	if (ret > 0)
		return ret;

	return ssl_err(con, ret, "SSL_read");
no_ssl:
#endif
	ret = read(con->sock, buf, count);
	if (ret <= 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return ret;
		
		if (ret != 0) {
			con->flags |= CNN_CLOSE;
			log_e("read");
		}
	}
	return ret;
}

int ssl_write(struct connection *con, void *buf, int count)
{
	int ret = -1;
#if (SSL_ENABLED)
	if (!con->ssl)
		goto no_ssl;

	ret = SSL_write(con->ssl, buf, count);
	if (ret > 0)
		return ret;

	return ssl_err(con, ret, "SSL_write");
no_ssl:
#endif
	ret = write(con->sock, buf, count);
	if (ret <= 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return ret;
		if (ret != 0) {
			con->flags |= CNN_CLOSE;
			log_e("write");
		}
	}
	return ret;
}

int ssl_accept(struct connection *con)
{
	int sock = -1;
	struct server_t *srv = con->srv; 

	sock = accept4(srv->sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (unlikely(sock < 0)) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
			log_e("accept4");
		return -1;
	}
	
	con->sock = sock;

#if (SSL_ENABLED)
	if (!srv->ssl_ctx)
		return sock;

	con->ssl = SSL_new(srv->ssl_ctx);
	if (!con->ssl)
		return -1;
		
	if (!SSL_set_fd(con->ssl, sock)) {
		log_e("SSL_set_fd() failed");
		return -1;
	}
	
	SSL_set_accept_state(con->ssl);
#endif
	
	return sock;
}

void ssl_handshake(struct connection *con)
{
#if (SSL_ENABLED)
	int ret = SSL_accept(con->ssl);
	if (ret == 1) {
		con->flags |= CNN_SSL_HANDSHAKE_DONE;
		return;
	}

	ssl_err(con, ret, "SSL_accept");
#endif
}

