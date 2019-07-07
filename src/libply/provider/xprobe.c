/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "xprobe.h"

#ifdef FNM_EXTMATCH
/* Support extended matching if we're on glibc. */
#  define PLY_FNM_FLAGS FNM_EXTMATCH
#else
#  define PLY_FNM_FLAGS 0
#endif

static int xprobe_stem(struct ply_probe *pb, char type, char *stem, size_t size)
{
	return snprintf(stem, size, "%c:%s/p%"PRIxPTR"_",
			type, pb->ply->group, (uintptr_t)pb);
}

static int __xprobe_create(FILE *ctrl, const char *stem, const char *func)
{
	char *funcname = strdup(func);
	char *offs;
	size_t i;

	assert(funcname);
	offs = strchr(funcname, '+');
	if (offs)
		*offs = '_';
	
	for(i = 0; 0x0 != funcname[i]; ++i)
		if ('.' == funcname[i])
			funcname[i] = '_';

	fputs(stem,     ctrl);
	fputs(funcname, ctrl);
	fputc( ' ',     ctrl);
	fputs(func,     ctrl);
	fputc('\n',     ctrl);

	free(funcname);
	return strlen(stem) + 2 * strlen(func) + 2;
}

static int __xprobe_delete(FILE *ctrl, const char *func)
{
	fputs("-:", ctrl);
	fputs(func, ctrl);
	fputc('\n', ctrl);

	return 2 + strlen(func) + 1;
}

static int xprobe_glob(struct ply_probe *pb, glob_t *gl)
{
	char *evglob;
	int err;

	asprintf(&evglob, TRACEPATH "events/%s/p%"PRIxPTR"_*",
		 pb->ply->group, (uintptr_t)pb);

	err = glob(evglob, 0, NULL, gl);
	free(evglob);
	return err ? -EINVAL : 0;
}

static int __xprobe_delete_all(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	glob_t gl;
	size_t i, evstart;
	int err, pending;

	err = xprobe_glob(pb, &gl);
	if (err)
		return err;

	if (gl.gl_pathc != xp->n_evs)
		_w("gl.gl_pathc (%d) != xp->n_evs (%d), failed to create some probes? (check dmesg for hints)\n", gl.gl_pathc, xp->n_evs);

	evstart = strlen(TRACEPATH "events/");
	pending = 0;

	for (i = 0; i < gl.gl_pathc; i++) {
		pending += __xprobe_delete(xp->ctrl, &gl.gl_pathv[i][evstart]);

		/* The kernel parser doesn't deal with a probe definition
		 * being split across two writes. So if there's less than
		 * 512 bytes left, flush the buffer. */
		if (pending > (0x1000 - 0x200)) {
			err = fflush(xp->ctrl);
			if (err)
				break;

			pending = 0;
		}
	}

	globfree(&gl);
	return err;
}

static int __xprobe_detach(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	size_t i;

	for (i = 0; i < xp->n_evs; i++)
		close(xp->evfds[i]);

	free(xp->evfds);
	xp->evfds = NULL;

	return 0; // no error at this moment
}

int xprobe_detach(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	int err;

	if (!xp->ctrl)
		return 0;

	err = __xprobe_detach(pb);
	if (err)
		goto err_close;

	err = __xprobe_delete_all(pb);
	if (err)
		goto err_close;

	if (!err)
		err = fflush(xp->ctrl) ? -errno : 0;

err_close:
	fclose(xp->ctrl);
	return err;
}


static int xprobe_create_pattern(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	struct ksym *sym;
	int err;

	ksyms_foreach(sym, pb->ply->ksyms) {
		if (fnmatch(xp->pattern, sym->sym, PLY_FNM_FLAGS))
			continue;

		__xprobe_create(xp->ctrl, xp->stem, sym->sym);
		xp->n_evs++;

		/* force flush, so we know the exact failing probe
		 */
		if (fflush(xp->ctrl))
			_w("Unable to create probe on %s, skipping\n", sym->sym);
	}

	return 0;
}	

static int xprobe_create(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	int err = 0;

	xprobe_stem(pb, xp->type, xp->stem, sizeof(xp->stem));

	if (strpbrk(xp->pattern, "?*[!@") && pb->ply->ksyms) {
		err = xprobe_create_pattern(pb);
	} else {
		__xprobe_create(xp->ctrl, xp->stem, xp->pattern);
		xp->n_evs++;
	}

	if (!err)
		err = fflush(xp->ctrl) ? -errno : 0;
	return err;
}

static int __xprobe_attach(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	glob_t gl;
	int err, i;

	err = xprobe_glob(pb, &gl);
	if (err)
		return err;

	if (gl.gl_pathc != xp->n_evs)
		_w("gl.gl_pathc (%d) != xp->n_evs (%d), failed to create some probes? (check dmesg for hints)\n", gl.gl_pathc, xp->n_evs);

	for (i = 0; i < (int)gl.gl_pathc; i++) {
		xp->evfds[i] = perf_event_attach(pb, gl.gl_pathv[i]);
		if (xp->evfds[i] < 0) {
			err = xp->evfds[i];
			break;
		}
	}

	globfree(&gl);
	return err;
}

int xprobe_attach(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;
	char *func;
	int err;

	/* TODO: mode should be a+ and we should clean this up on
	 * detach. */
	xp->ctrl = fopenf("a+", TRACEPATH "%s", xp->ctrl_name);
	if (!xp->ctrl)
		return -errno;

	err = setvbuf(xp->ctrl, NULL, _IOFBF, 0x1000);
	if (err) {
		err = -errno;
		goto err_close;
	}

	err = xprobe_create(pb);
	if (err)
		goto err_close;

	xp->evfds = xcalloc(xp->n_evs, sizeof(xp->evfds));

	err = __xprobe_attach(pb);
	if (err)
		goto err_detach;

	return 0;

err_detach:
	__xprobe_detach(pb);

err_close:
	__xprobe_delete_all(pb);
	fclose(xp->ctrl);
	return err;
}
