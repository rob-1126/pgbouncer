/*-------------------------------------------------------------------------
 *
 * proto_fromlibpq.c
 *	   Postgres-licensed portions of stuff that would otherwise be in proto.c
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *-------------------------------------------------------------------------
 */
#include <krb5.h>	/* for krb5_get_default_realm() */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "bouncer.h"
#include "scram.h"
#include "proto_fromlibpq.h"


// hrmm probably should find a better name for this
enum GssStatus {STATUS_OK = 0, STATUS_ERROR};




/* Helper to translate GSSAPI status codes into human-readable text */
static void log_gss_status(const char *label, OM_uint32 code, int status_type)
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

static bool gss_load_servicename(PgSocket *server)
{
	OM_uint32 maj_stat, min_stat, ctx_min;
	gss_buffer_desc buf;
	const char *base_spn;
	char *spn_alloc = NULL;
	gss_OID name_type;

	if (cf_server_krb_spn && *cf_server_krb_spn) {
		/* admin explicitly set it → treat as full principal */
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
		log_gss_status("GSS import major", maj_stat, GSS_C_GSS_CODE);
		log_gss_status("GSS import minor", min_stat, GSS_C_MECH_CODE);
		return false;
	}

	/* Canonicalize for Kerberos mech and display the true principal */
	{
		gss_name_t canon = GSS_C_NO_NAME;
		maj_stat = gss_canonicalize_name(
			&min_stat,
			server->gss.name,
			(gss_OID) gss_mech_krb5,
			&canon
			);
		if (maj_stat != GSS_S_COMPLETE) {
			slog_error(server, "gss_canonicalize_name failed maj=%u min=%u",
				   maj_stat, min_stat);
			log_gss_status("GSS canonicalize major", maj_stat, GSS_C_GSS_CODE);
			log_gss_status("GSS canonicalize minor", min_stat, GSS_C_MECH_CODE);
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

bool login_gss_cont(PgSocket *server, unsigned datalen, const uint8_t *data)
{
	OM_uint32 maj_stat, min_stat, lmin_s;
	gss_buffer_desc ginbuf;
	gss_buffer_desc goutbuf = GSS_C_EMPTY_BUFFER;
	bool res = false;

	/* Initial leg: import & canonicalize service name */
	if (server->gss.state == GSS_INITIAL) {
		slog_info(server, "gssapi continuation start");
		ginbuf.value = NULL;
		ginbuf.length = 0;

		if (!gss_load_servicename(server))
			return false;

		/* Canonicalize name for Kerberos mechanism */
		gss_name_t canon = GSS_C_NO_NAME;
		maj_stat = gss_canonicalize_name(
			&min_stat,
			server->gss.name,
			(gss_OID) gss_mech_krb5,
			&canon
			);
		slog_info(server, "gss_canonicalize_name major=%u minor=%u", maj_stat, min_stat);
		if (maj_stat != GSS_S_COMPLETE) {
			log_gss_status("GSS canonicalize major", maj_stat, GSS_C_GSS_CODE);
			log_gss_status("GSS canonicalize minor", min_stat, GSS_C_MECH_CODE);
			gss_release_name(&lmin_s, &server->gss.name);
			return false;
		}

		gss_release_name(&lmin_s, &server->gss.name);
		server->gss.name = canon;
		server->gss.ctx = GSS_C_NO_CONTEXT;
		server->gss.state = GSS_CONTINUE;
	} else {
		ginbuf.length = datalen;
		ginbuf.value = malloc(datalen);
		if (!ginbuf.value) {
			slog_error(server, "out of memory allocating gssapi buffer");
			return false;
		}
		memcpy(ginbuf.value, data, datalen);
	}

	/* Perform next GSS handshake step */
	slog_info(server, "preparing to call gss_init_sec_context");
	maj_stat = gss_init_sec_context(
		&min_stat,
		GSS_C_NO_CREDENTIAL,
		&server->gss.ctx,
		server->gss.name,
		(gss_const_OID) gss_mech_krb5,
		GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG,
		0,
		GSS_C_NO_CHANNEL_BINDINGS,
		(ginbuf.value ? &ginbuf : GSS_C_NO_BUFFER),
		NULL,
		&goutbuf,
		NULL,
		NULL
		);
	slog_info(server, "got gss_init_sec_context result %u minor %u", maj_stat, min_stat);

	if (ginbuf.value) free(ginbuf.value);

	/* Error handling */
	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
		slog_error(server, "GSSAPI continuation error maj %u min %u", maj_stat, min_stat);
		log_gss_status("GSS major status", maj_stat, GSS_C_GSS_CODE);
		log_gss_status("GSS minor status", min_stat, GSS_C_MECH_CODE);
		gss_release_buffer(&lmin_s, &goutbuf);
		gss_release_name(&lmin_s, &server->gss.name);
		gss_delete_sec_context(&lmin_s, &server->gss.ctx, GSS_C_NO_BUFFER);
		return false;
	}

	/* Send token to client */
	if (goutbuf.length > 0) {
		slog_info(server, "Sending GSSResponseMessage of length %zu", goutbuf.length);
		SEND_GSSResponseMessage(res, server, goutbuf.value, goutbuf.length);
		gss_release_buffer(&lmin_s, &goutbuf);
	}

	/* Finalize */
	if (maj_stat == GSS_S_COMPLETE) {
		gss_release_name(&lmin_s, &server->gss.name);
		server->gss.state = GSS_DONE;
	}

	return true;
}
