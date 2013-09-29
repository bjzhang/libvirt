/*
 * libxl_domain.h: libxl domain object private state
 *
 * Copyright (C) 2011-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Jim Fehlig <jfehlig@suse.com>
 */

#ifndef LIBXL_DOMAIN_H
# define LIBXL_DOMAIN_H

# include <libxl.h>

# include "domain_conf.h"
# include "libxl_conf.h"
# include "virchrdev.h"
# include "virobject.h"

# define JOB_MASK(job)                  (1 << (job - 1))
# define DEFAULT_JOB_MASK               \
    (JOB_MASK(LIBXL_JOB_DESTROY) |      \
     JOB_MASK(LIBXL_JOB_ABORT))

/* Only 1 job is allowed at any time
 * A job includes *all* libxl.so api, even those just querying
 * information, not merely actions */
enum libxlDomainJob {
    LIBXL_JOB_NONE = 0,      /* Always set to 0 for easy if (jobActive) conditions */
    LIBXL_JOB_QUERY,         /* Doesn't change any state */
    LIBXL_JOB_DESTROY,       /* Destroys the domain (cannot be masked out) */
    LIBXL_JOB_MODIFY,        /* May change state */

    LIBXL_JOB_LAST
};
VIR_ENUM_DECL(libxlDomainJob)


struct libxlDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum libxlDomainJob active;         /* Currently running job */
    int owner;                          /* Thread which set current job */
};

int ao_how_enable;
int ao_how_enable_cb;

typedef struct _libxlDomainAo libxlDomainAo;
typedef libxlDomainAo *libxlDomainAoPtr;
struct _libxlDomainAo {
    libxl_asyncop_how ao_how;
    int ao_complete;
};

typedef struct _libxlChildInfo libxlChildInfo;
typedef libxlChildInfo *libxlChildInfoPtr;
struct _libxlChildInfo {
    virObjectLockable parent;
    pid_t pid;
    int status;
    int called;
    int pending;
};

typedef struct _libxlChildrenObj libxlChildrenObj;
typedef libxlChildrenObj *libxlChildrenObjPtr;
struct _libxlChildrenObj {
    virObjectLockable parent;

    virHashTable *objs;
    libxl_ctx *ctx;
};

////TODO: dymanic malloc child info
//#define MAX_CHILD 10
//typedef _libxlPerSigchildInfo libxlPerSigchildInfo;
//typedef libxlPerSigchildInfo *libxlPerSigchildInfoPtr;
//struct _libxlPerSigchildInfo {
//    pid_t pid;
//    int status;
//    int called;
//    int pending;
//};
//
//typedef _libxlSigchildInfo libxlSigchildInfo;
//typedef libxlSigchildInfo libxlSigchildInfoPtr;
//struct _libxlSigchildInfo {
//    libxl_ctx *ctx;//TODO do i need this? how about get this by container_of
//    int id;
//    per_sigchild_info child[MAX_CHILD];
//};
//sigchild_info child_info;

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
typedef libxlDomainObjPrivate *libxlDomainObjPrivatePtr;
struct _libxlDomainObjPrivate {
    virObjectLockable parent;

    /* per domain log stream for libxl messages */
    FILE *logger_file;
    xentoollog_logger *logger;
    /* per domain libxl ctx */
    libxl_ctx *ctx;
    /* console */
    virChrdevsPtr devs;
    libxl_evgen_domain_death *deathW;

    /* list of libxl timeout registrations */
    libxlEventHookInfoPtr timerRegistrations;

    struct libxlDomainJobObj job;

    libxlDomainAo ao;

    libxlChildrenObj children;
};

extern virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks;
extern virDomainDefParserConfig libxlDomainDefParserConfig;

extern libxlChildrenHashPtr children_hash;

int
libxlDomainObjPrivateInitCtx(virDomainObjPtr vm);

void
libxlDomainObjRegisteredTimeoutsCleanup(libxlDomainObjPrivatePtr priv);

int
libxlDomainObjBeginJob(libxlDriverPrivatePtr driver,
                       virDomainObjPtr obj,
                       enum libxlDomainJob job)
    ATTRIBUTE_RETURN_CHECK;

bool
libxlDomainObjEndJob(libxlDriverPrivatePtr driver,
                     virDomainObjPtr obj)
    ATTRIBUTE_RETURN_CHECK;

void
ao_how_init(libxlDomainObjPrivatePtr priv ATTRIBUTE_UNUSED);
void
ao_how_wait(libxlDriverPrivatePtr driver, virDomainObjPtr vm);

#endif /* LIBXL_DOMAIN_H */
