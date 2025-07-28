/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <krb5.h>	/* for krb5_get_default_realm() */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "bouncer.h"
#include "scram.h"
#include "gssauth.h"


enum GssStatus {STATUS_OK = 0, STATUS_ERROR};


/* Helper to translate GSSAPI status codes into human-readable text */
static void gss_log_status(const char *label, OM_uint32 code, int status_type)
{
	OM_uint32 msg_ctx = 0, min_stat;
	gss_buffer_desc status_msg;

	do {
		gss_display_status(
			&min_stat,
			code,
			status_type,
			GSS_C_NO_OID,
			&msg_ctx,
			&status_msg
			);
		slog_error(NULL, "%s: %.*s", label,
			   (int)status_msg.length, (char *)status_msg.value);
		gss_release_buffer(&min_stat, &status_msg);
	} while (msg_ctx);
}

static bool gss_prepare_server_name(PgSocket *server)
{
	OM_uint32 maj_stat, min_stat, ctx_min;
	gss_buffer_desc buf;
	const char *base_spn;
	char *spn_alloc = NULL;
	gss_OID name_type;

	if (server->pool &&
	    server->pool->db &&
	    server->pool->db->server_krb_spn &&
	    *server->pool->db->server_krb_spn) {
		/* explicitly set at the db level, use it as literal complete spn */
		base_spn = server->pool->db->server_krb_spn;
		name_type = GSS_C_NT_USER_NAME;
	} else if (cf_server_krb_spn && *cf_server_krb_spn) {
		/* explicitly set on the global level, use it as literal complete spn */
		base_spn = cf_server_krb_spn;
		name_type = GSS_C_NT_USER_NAME;
	} else {
		/* no override → build postgres/host@REALM automatically */
		krb5_context kctx = NULL;
		char *default_realm = NULL;

		if (krb5_init_context(&kctx) == 0 &&
		    krb5_get_default_realm(kctx, &default_realm) == 0) {
			size_t len = strlen("postgres/") +
				     strlen(server->pool->db->host) +
				     1 +/* “@” */
				     strlen(default_realm) +
				     1;	/* NUL */
			spn_alloc = malloc(len);
			if (!spn_alloc) {
				slog_error(server, "out of memory allocating SPN buffer");
				krb5_free_context(kctx);
				return false;
			}
			snprintf(spn_alloc, len, "postgres/%s@%s",
				 server->pool->db->host, default_realm);

			krb5_free_default_realm(kctx, default_realm);
			krb5_free_context(kctx);

			base_spn = spn_alloc;
			name_type = GSS_C_NT_USER_NAME;
		} else {
			/* fallback (should almost never happen): host‐based */
			size_t len = strlen("postgres@") +
				     strlen(server->pool->db->host) +
				     1;
			spn_alloc = malloc(len);
			if (!spn_alloc) {
				slog_error(server, "out of memory allocating SPN buffer");
				if (kctx) krb5_free_context(kctx);
				return false;
			}
			snprintf(spn_alloc, len, "postgres@%s", server->pool->db->host);
			if (kctx) krb5_free_context(kctx);

			base_spn = spn_alloc;
			name_type = GSS_C_NT_HOSTBASED_SERVICE;
		}
	}

	buf.value = (void *)base_spn;
	buf.length = strlen(base_spn);

	slog_info(server, "importing service principal %s", base_spn);
	maj_stat = gss_import_name(&min_stat,
				   &buf,
				   name_type,
				   &server->gss.name);
	if (spn_alloc)
		free(spn_alloc);

	if (maj_stat != GSS_S_COMPLETE) {
		slog_error(server, "gss_import_name failed maj=%u min=%u",
			   maj_stat, min_stat);
		gss_log_status("GSS import major", maj_stat, GSS_C_GSS_CODE);
		gss_log_status("GSS import minor", min_stat, GSS_C_MECH_CODE);
		return false;
	}

	/* Canonicalize for Kerberos mech and display the true principal */
	{
		gss_name_t canon;
		canon = GSS_C_NO_NAME;
		maj_stat = gss_canonicalize_name(
			&min_stat,
			server->gss.name,
			(gss_OID) gss_mech_krb5,
			&canon
			);
		if (maj_stat != GSS_S_COMPLETE) {
			slog_error(server, "gss_canonicalize_name failed maj=%u min=%u",
				   maj_stat, min_stat);
			gss_log_status("GSS canonicalize major", maj_stat, GSS_C_GSS_CODE);
			gss_log_status("GSS canonicalize minor", min_stat, GSS_C_MECH_CODE);
			gss_release_name(&ctx_min, &server->gss.name);
			return false;
		}
		gss_release_name(&ctx_min, &server->gss.name);
		server->gss.name = canon;
	}

	{
		/* now this will include “@YOURREALM” on host-based fallbacks too */
		gss_buffer_desc namebuf;
		OM_uint32 dbg_min;
		gss_display_name(&dbg_min, server->gss.name, &namebuf, NULL);
		slog_info(server, "using target service principal %.*s",
			  (int)namebuf.length, (char *)namebuf.value);
		gss_release_buffer(&dbg_min, &namebuf);
	}

	return true;
}

/* ----------------------------------------------------------------------
 *  Small helpers used by gss_auth_step()
 * ---------------------------------------------------------------------- */

/*
 * Allocate and copy the incoming token (if any) into a GSS buffer.
 * Returns true on success; false on OOM.
 */
static bool gss_copy_client_token(gss_buffer_desc *dst,
				  unsigned datalen,
				  const uint8_t *data,
				  PgSocket *server)
{
	if (datalen == 0) {
		dst->length = 0;
		dst->value = NULL;
		return true;
	}

	dst->value = malloc(datalen);
	if (!dst->value) {
		slog_error(server, "out of memory allocating gssapi buffer");
		return false;
	}
	memcpy(dst->value, data, datalen);
	dst->length = datalen;
	return true;
}

/*
 * Prepare server->gss.name and server->gss.ctx for the very first leg.
 * Returns true on success, false on failure.
 */
static bool gss_begin_first_leg(PgSocket *server)
{
	OM_uint32 maj_stat, min_stat, tmp;
	gss_name_t canon;

	if (!gss_prepare_server_name(server))
		return false;

	/* Kerberos‑specific canonicalisation */
	canon = GSS_C_NO_NAME;
	maj_stat = gss_canonicalize_name(&min_stat,
					 server->gss.name,
					 (gss_OID) gss_mech_krb5,
					 &canon);
	slog_info(server, "gss_canonicalize_name major=%u minor=%u",
		  maj_stat, min_stat);

	if (maj_stat != GSS_S_COMPLETE) {
		gss_log_status("GSS canonicalize major", maj_stat, GSS_C_GSS_CODE);
		gss_log_status("GSS canonicalize minor", min_stat, GSS_C_MECH_CODE);
		gss_release_name(&tmp, &server->gss.name);
		return false;
	}

	gss_release_name(&tmp, &server->gss.name);
	server->gss.name = canon;
	server->gss.ctx = GSS_C_NO_CONTEXT;
	server->gss.state = GSS_CONTINUE;
	return true;
}

/*
 * Call gss_init_sec_context() for this step.
 * Returns the major status; fills in *gout.
 */
static OM_uint32 gss_do_one_handshake_step(PgSocket *server,
					   const gss_buffer_desc *gin,
					   gss_buffer_desc *gout,
					   OM_uint32 *p_min_stat)
{
	return gss_init_sec_context(p_min_stat,
				    GSS_C_NO_CREDENTIAL,
				    &server->gss.ctx,
				    server->gss.name,
				    (gss_OID) gss_mech_krb5,
				    GSS_C_MUTUAL_FLAG |
				    GSS_C_INTEG_FLAG  |
				    GSS_C_SEQUENCE_FLAG,
				    0,
				    GSS_C_NO_CHANNEL_BINDINGS,
				    (gin->value ? (gss_buffer_t)gin : GSS_C_NO_BUFFER),
				    NULL,
				    gout,
				    NULL,
				    NULL);
}

/* Send the output token to the client, if any. */
static void gss_send_token(PgSocket *server, const gss_buffer_desc *buf)
{
	bool sent = false;

	if (buf->length == 0)
		return;

	slog_info(server, "Sending GSSResponseMessage of length %zu", buf->length);
	SEND_GSSResponseMessage(sent, server, buf->value, buf->length);
	(void)sent;		/* macro sets it but we do not need the result */
}

/*
 * Finalise when the security context is fully established.
 */
static void gss_finish_success(PgSocket *server)
{
	OM_uint32 tmp;
	gss_release_name(&tmp, &server->gss.name);
	server->gss.state = GSS_DONE;
}

/*
 * gss_auth_step —— drive one iteration of the server’s GSSAPI handshake
 *
 * This function handles both the initial leg and subsequent continuations
 * of a GSSAPI security context exchange with the client. On the first call,
 * it prepares and canonicalizes the service principal name, then for every
 * invocation it imports the client’s incoming token (if any), calls
 * gss_init_sec_context to advance the handshake, and sends back any output
 * token. If the call completes the context (GSS_S_COMPLETE), it finalizes
 * by releasing the server name and marking the context state as DONE.
 *
 * Bringing our own gss_auth_step instead of borrowing from libpq
 * allows us introduce a configurable option to specify a specific krb
 * spn.
 *
 * Returns true on success (handshake ongoing or complete), false on fatal error.
 */
bool gss_auth_step(PgSocket *server, unsigned datalen, const uint8_t *data)
{
	OM_uint32 maj_stat, min_stat, tmp;
	gss_buffer_desc gin = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gout = GSS_C_EMPTY_BUFFER;

	/* 1) First‑leg initialization */
	if (server->gss.state == GSS_INITIAL) {
		slog_info(server, "gssapi continuation start");
		if (!gss_begin_first_leg(server))
			return false;
	}

	/* 2) Copy client token */
	if (!gss_copy_client_token(&gin, datalen, data, server))
		return false;

	/* 3) Perform one step of the handshake */
	slog_info(server, "preparing to call gss_init_sec_context");
	maj_stat = gss_do_one_handshake_step(server, &gin, &gout, &min_stat);
	slog_info(server, "got gss_init_sec_context result %u minor %u",
		  maj_stat, min_stat);

	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
		slog_error(server, "GSSAPI continuation error maj %u min %u",
			   maj_stat, min_stat);
		gss_log_status("GSS major status", maj_stat, GSS_C_GSS_CODE);
		gss_log_status("GSS minor status", min_stat, GSS_C_MECH_CODE);

		/* error cleanup */
		if (gin.value) free(gin.value);
		gss_release_buffer(&tmp, &gout);
		gss_release_name(&tmp, &server->gss.name);
		gss_delete_sec_context(&tmp, &server->gss.ctx, GSS_C_NO_BUFFER);
		return false;
	}

	/* 4) Send the output token, if any */
	gss_send_token(server, &gout);

	/* 5) On final success, release name and mark DONE */
	if (maj_stat == GSS_S_COMPLETE)
		gss_finish_success(server);

	/* normal cleanup */
	if (gin.value) free(gin.value);
	gss_release_buffer(&tmp, &gout);
	return true;
}
