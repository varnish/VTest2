/*-
 * Copyright (c) 2008-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The stuff extensions should/will need to function
 */

struct vtclog;

#define VTC_CHECK_NAME(vl, nm, type, chr)				\
	do {								\
		AN(nm);							\
		if (*(nm) != chr)					\
			vtc_fatal(vl,					\
			    type " name must start with '%c' (got %s)",	\
			    chr, nm);					\
	} while (0)

#define	CMD_ARGS char * const *av, void *priv, struct vtclog *vl
#define	CMDS_F_NONE		0x0
#define	CMDS_F_GLOBAL		0x1
#define	CMDS_F_SHUT		0x2

typedef void cmd_f(CMD_ARGS);

struct cmds {
	unsigned		magic;
#define CMDS_MAGIC		0x9ccc797d
	const char		*name;
	cmd_f			*cmd;
	unsigned		flags;
};

extern vtim_dur vtc_maxdur;
extern int vtc_stop;		/* Abandon current test, no error */
extern volatile sig_atomic_t vtc_error; /* Error, bail out */
extern int leave_temp;
extern const char *default_listen_addr;
extern char *vmod_path;
extern struct vsb *params_vsb;
extern pthread_t vtc_thread;

void parse_string(struct vtclog *vl, void *priv, const char *spec);

void add_cmd(const char *name, cmd_f *cmd, unsigned flags);

void vtc_dump(struct vtclog *vl, int lvl, const char *pfx,
    const char *str, int len);

void vtc_fatal(struct vtclog *vl, const char *, ...)
    v_noreturn_ v_printflike_(2,3);

void vtc_log(struct vtclog *vl, int lvl, const char *fmt, ...)
    v_printflike_(3, 4);

void vtc_log_set_cmd(struct vtclog *vl, const struct cmds *cmds);

void *vtc_record(struct vtclog *, int, struct vsb *);
void vtc_logclose(void *arg);
struct vtclog *vtc_logopen(const char *id, ...) v_printflike_(1, 2);
void vtc_wait4(struct vtclog *, long, int, int, int);

void cmd_server_gen_vcl(struct vsb *vsb);

void macro_undef(struct vtclog *vl, const char *instance, const char *name);
void macro_def(struct vtclog *vl, const char *instance, const char *name,
    const char *fmt, ...) v_printflike_(4, 5);
void macro_cat(struct vtclog *, struct vsb *, const char *, const char *);
unsigned macro_isdef(const char *instance, const char *name);
struct vsb *macro_expand(struct vtclog *vl, const char *text);
struct vsb *macro_expandf(struct vtclog *vl, const char *, ...)
    v_printflike_(2, 3);
