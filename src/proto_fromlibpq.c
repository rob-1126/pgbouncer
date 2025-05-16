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

#include "bouncer.h"
#include "scram.h"
#include "proto_fromlibpq.h"

// hrmm probably should find a better name for this
enum GssStatus {STATUS_OK = 0, STATUS_ERROR};



 /*
  * Try to load service name for a connection
  */
static int
gss_load_servicename(PgSocket *server)
{
    OM_uint32         maj_stat,
                      min_stat;
    gss_buffer_desc   temp_gbuf;
    const char       *spn;
    char             *spn_alloc = NULL;

    /* 1) explicit override wins */
    if (cf_server_krb_spn && *cf_server_krb_spn) {
        spn = cf_server_krb_spn;
    }
    else {
        /* default to "postgres@<host>" */
        size_t len = strlen("postgres@") + strlen(server->pool->db->host) + 1;
        spn_alloc = malloc(len);
        if (!spn_alloc) {
            slog_error(server, "out of memory allocating SPN buffer");
            return STATUS_ERROR;
        }
        snprintf(spn_alloc, len, "postgres@%s", server->pool->db->host);
        spn = spn_alloc;
    }

    temp_gbuf.value  = (void *) spn;
    temp_gbuf.length = strlen(spn);

    slog_info(server, "asking for target service principal %s", spn);
    slog_info(server, "Calling gss_import_name");
    maj_stat = gss_import_name(&min_stat,
                               &temp_gbuf,
                               GSS_C_NT_HOSTBASED_SERVICE,
                               &server->gss.name);
    slog_info(server,
             "Done calling gss_import_name - maj_stat=%u min_stat=%u",
             maj_stat, min_stat);

    if (spn_alloc)
        free(spn_alloc);

    if (maj_stat != GSS_S_COMPLETE) {
        slog_error(server, "GSSAPI name import error");
        return STATUS_ERROR;
    }

    return STATUS_OK;
}



bool login_gss_cont(PgSocket *server, unsigned datalen, const uint8_t *data)
{
	OM_uint32	maj_stat,
				min_stat,
				lmin_s;
	gss_buffer_desc ginbuf;
	gss_buffer_desc goutbuf;
	bool ret; /* return value of gss_load_servicename */
	bool res; /* response from send of resulting continuation */

	if (GSS_INITIAL == server->gss.state) {
 		slog_info(server, "gssapi continuation start");
		ginbuf.length = 0;
		ginbuf.value = NULL;
		ret = gss_load_servicename(server);
		if (ret != STATUS_OK)
			return ret;

   		server->gss.state = GSS_CONTINUE;
  	}
	else {
		slog_error(server, "gssapi continuation in login_gss_cont not yet implemented");
		ginbuf.value = malloc(datalen + 1);
		if (!ginbuf.value) {
			slog_error(server, "out of error allocating gssapi buffer");
			return false;
		}
		memcpy(ginbuf.value, data, datalen);

		// TODO FIGURE OUT WHY THIS IS BORK
		//ginbuf.value[datalen] = '\0';
	}
	slog_info(server, "preparing to call gss_init_sec_context");
	server->gss.ctx = GSS_C_NO_CONTEXT;
	maj_stat = gss_init_sec_context(&min_stat,
								GSS_C_NO_CREDENTIAL,
								&server->gss.ctx,
								server->gss.name,
								GSS_C_NO_OID,
								GSS_C_MUTUAL_FLAG,
								0,
								GSS_C_NO_CHANNEL_BINDINGS,
								(ginbuf.value == NULL) ? GSS_C_NO_BUFFER : &ginbuf,
								NULL,
								&goutbuf,
								NULL,
								NULL);
	if(server->gss.ctx == GSS_C_NO_CONTEXT) {
		slog_info(server, "no new gss context was created");
	}
	slog_info(server, "got gss_init_sec_context result %u %u", maj_stat, min_stat);

	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {	
		slog_info(server, "GSSAPI continuation error maj %u min %u", maj_stat, min_stat);
		return STATUS_ERROR;
	}

	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {	
		slog_info(server, "GSSAPI continuation error maj %u min %u", maj_stat, min_stat);
		return STATUS_ERROR;
	}

	if (ginbuf.value)
		free(ginbuf.value);

	if (goutbuf.length != 0)
	{
		slog_info(server, "Sending GSSResponseMessage of length %zu", goutbuf.length);
		SEND_GSSResponseMessage(res, server, goutbuf.value, goutbuf.length);
	}
	gss_release_buffer(&lmin_s, &goutbuf);

	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	{
		slog_error(server, "gssapi continuation error - maj_stat value was %u", maj_stat);
		gss_release_name(&lmin_s, &server->gss.name);
		if (server->gss.state)
			gss_delete_sec_context(&lmin_s, &server->gss.ctx, GSS_C_NO_BUFFER);
		return false;
	}

	if (maj_stat == GSS_S_COMPLETE)
		gss_release_name(&lmin_s, &server->gss.name);

	return res;

}