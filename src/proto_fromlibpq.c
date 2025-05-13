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
 static int gss_load_servicename(PgSocket *server)
 {
     OM_uint32   maj_stat,
                 min_stat;
     int         maxlen;
     gss_buffer_desc temp_gbuf;
     char       *host;
	 char		*krbsrvname;

	 krbsrvname = "postgres";
     //host = "kpsql.robs-desktop-again.astronomer-trials.com";
	 //PGconn *conn = server->pool->db->host;
     //host = PQhost(conn);
     host = server->pool->db->host;
	 
     /*
      * Import service principal name so the proper ticket can be acquired by
      * the GSSAPI system.
      */
     maxlen = strlen(krbsrvname) + strlen(host) + 2;
     temp_gbuf.value = (char *) malloc(maxlen);
     if (!temp_gbuf.value)
     {
         slog_error(server, "ran out of memory allocating buffer during gss_load_servicename");
         return STATUS_ERROR;
     }

	 snprintf(temp_gbuf.value, maxlen, "%s@%s",
			krbsrvname, host);

     slog_info(server, "asking for target service principal %s", (char *)temp_gbuf.value);

     temp_gbuf.length = strlen(temp_gbuf.value);
	 // GSS_C_NT_HOSTBASED_SERVICE tells it to map service@host to service/primary-host@realm
	 // and is what is used by the postgres client so we blindly follow
     slog_info(server, "Calling gss_import_name");
     maj_stat = gss_import_name(&min_stat, &temp_gbuf,
                                GSS_C_NT_HOSTBASED_SERVICE, &server->gss.name);
	 

     slog_info(server, "Done calling gss_import_name - maj_stat value was %u min_stat value was %u", maj_stat, min_stat);
     free(temp_gbuf.value);
  
     if (maj_stat != GSS_S_COMPLETE)
     {
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