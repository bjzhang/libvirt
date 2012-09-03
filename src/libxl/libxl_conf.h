/*---------------------------------------------------------------------------*/
/*  Copyright (c) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *  Copyright (C) 2011 Univention GmbH.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Jim Fehlig <jfehlig@novell.com>
 *     Markus Groß <gross@univention.de>
 */
/*---------------------------------------------------------------------------*/

#ifndef LIBXL_CONF_H
# define LIBXL_CONF_H

# include <config.h>

# include <libxl.h>

# include "internal.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "capabilities.h"
# include "configmake.h"
# include "bitmap.h"


# define LIBXL_VNC_PORT_MIN  5900
# define LIBXL_VNC_PORT_MAX  65535

# define LIBXL_CONFIG_DIR SYSCONFDIR "/libvirt/libxl"
# define LIBXL_AUTOSTART_DIR LIBXL_CONFIG_DIR "/autostart"
# define LIBXL_STATE_DIR LOCALSTATEDIR "/run/libvirt/libxl"
# define LIBXL_LOG_DIR LOCALSTATEDIR "/log/libvirt/libxl"
# define LIBXL_LIB_DIR LOCALSTATEDIR "/lib/libvirt/libxl"
# define LIBXL_SAVE_DIR LIBXL_LIB_DIR "/save"


typedef struct _libxlDriverPrivate libxlDriverPrivate;
typedef libxlDriverPrivate *libxlDriverPrivatePtr;
struct _libxlDriverPrivate {
    virMutex lock;
    virCapsPtr caps;
    unsigned int version;

    FILE *logger_file;
    xentoollog_logger *logger;
    /* libxl ctx for driver wide ops; getVersion, getNodeInfo, ... */
    libxl_ctx ctx;

    virBitmapPtr reservedVNCPorts;
    virDomainObjList domains;

    virDomainEventStatePtr domainEventState;

    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    char *libDir;
    char *saveDir;
};

# define JOB_MASK(job)                  (1 << (job - 1))
# define DEFAULT_JOB_MASK               \
    (JOB_MASK(LIBXL_JOB_DESTROY) |      \
     JOB_MASK(LIBXL_JOB_ABORT))

/* Jobs which have to be tracked in domain state XML. */
# define LIBXL_DOMAIN_TRACK_JOBS        \
    (JOB_MASK(LIBXL_JOB_DESTROY) |      \
     JOB_MASK(LIBXL_JOB_ASYNC))

/* Only 1 job is allowed at any time
 * A job includes *all* libxl.so api, even those just querying
 * information, not merely actions */
enum libxlDomainJob {
    LIBXL_JOB_NONE = 0,      /* Always set to 0 for easy if (jobActive) conditions */
    LIBXL_JOB_DESTROY,       /* Destroys the domain (cannot be masked out) */
    LIBXL_JOB_MODIFY,        /* May change state */
    LIBXL_JOB_ABORT,         /* Abort current async job */
    LIBXL_JOB_MIGRATION_OP,  /* Operation influencing outgoing migration */

    /* The following two items must always be the last items before JOB_LAST */
    LIBXL_JOB_ASYNC,         /* Asynchronous job */

    LIBXL_JOB_LAST
};
VIR_ENUM_DECL(libxlDomainJob)

/* Async job consists of a series of jobs that may change state. Independent
 * jobs that do not change state (and possibly others if explicitly allowed by
 * current async job) are allowed to be run even if async job is active.
 */
enum libxlDomainAsyncJob {
    LIBXL_ASYNC_JOB_NONE = 0,
    LIBXL_ASYNC_JOB_MIGRATION_OUT,
    LIBXL_ASYNC_JOB_MIGRATION_IN,
    LIBXL_ASYNC_JOB_SAVE,
    LIBXL_ASYNC_JOB_RESTORE,
    LIBXL_ASYNC_JOB_DUMP,

    LIBXL_ASYNC_JOB_LAST
};
VIR_ENUM_DECL(libxlDomainAsyncJob)

struct libxlDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum libxlDomainJob active;         /* Currently running job */
    int owner;                          /* Thread which set current job */

    virCond asyncCond;                  /* Use to coordinate with async jobs */
    enum libxlDomainAsyncJob asyncJob;  /* Currently active async job */
    int asyncOwner;                     /* Thread which set current async job */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    unsigned long long start;           /* When the async job started */
    virDomainJobInfo info;              /* Async job progress data */
};

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
typedef libxlDomainObjPrivate *libxlDomainObjPrivatePtr;
struct _libxlDomainObjPrivate {
    /* per domain libxl ctx */
    libxl_ctx ctx;
    libxl_waiter *dWaiter;
    int waiterFD;
    int eventHdl;

    struct libxlDomainJobObj job;
};

# define LIBXL_SAVE_MAGIC "libvirt-xml\n \0 \r"
# define LIBXL_SAVE_VERSION 1

typedef struct _libxlSavefileHeader libxlSavefileHeader;
typedef libxlSavefileHeader *libxlSavefileHeaderPtr;
struct _libxlSavefileHeader {
    char magic[sizeof(LIBXL_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t xmlLen;
    /* 24 bytes used, pad up to 64 bytes */
    uint32_t unused[10];
};

virCapsPtr
libxlMakeCapabilities(libxl_ctx *ctx);

int
libxlMakeDisk(virDomainDefPtr def, virDomainDiskDefPtr l_dev,
              libxl_device_disk *x_dev);
int
libxlMakeNic(virDomainDefPtr def, virDomainNetDefPtr l_nic,
             libxl_device_nic *x_nic);
int
libxlMakeVfb(libxlDriverPrivatePtr driver, virDomainDefPtr def,
             virDomainGraphicsDefPtr l_vfb, libxl_device_vfb *x_vfb);

int
libxlBuildDomainConfig(libxlDriverPrivatePtr driver,
                       virDomainDefPtr def, libxl_domain_config *d_config);

#endif /* LIBXL_CONF_H */
