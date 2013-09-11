/*
 * libxl_domain.c: libxl domain object private state
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

#include <config.h>

#include "libxl_conf.h"
#include "libxl_domain.h"

#include "viralloc.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL


VIR_ENUM_IMPL(libxlDomainJob, LIBXL_JOB_LAST,
              "none",
              "query",
              "destroy",
              "modify",
);

/* Append an event registration to the list of registrations */
#define LIBXL_EV_REG_APPEND(head, add)                 \
    do {                                               \
        libxlEventHookInfoPtr temp;                    \
        if (head) {                                    \
            temp = head;                               \
            while (temp->next)                         \
                temp = temp->next;                     \
            temp->next = add;                          \
        } else {                                       \
            head = add;                                \
        }                                              \
    } while (0)

/* Remove an event registration from the list of registrations */
#define LIBXL_EV_REG_REMOVE(head, del)                 \
    do {                                               \
        libxlEventHookInfoPtr temp;                    \
        if (head == del) {                             \
            head = head->next;                         \
        } else {                                       \
            temp = head;                               \
            while (temp->next && temp->next != del)    \
                temp = temp->next;                     \
            if (temp->next) {                          \
                temp->next = del->next;                \
            }                                          \
        }                                              \
    } while (0)

/* Object used to store info related to libxl event registrations */
struct _libxlEventHookInfo {
    libxlEventHookInfoPtr next;
    libxlDomainObjPrivatePtr priv;
    void *xl_priv;
    int id;
};

#define MAX_CHILD 100
typedef struct {
    pid_t pid;
    int status;
    int called;
    int pending;
} per_sigchild_info;

typedef struct {
    libxl_ctx *ctx;
    int id;
    per_sigchild_info child[MAX_CHILD];
} sigchild_info;
sigchild_info child_info;

libxl_asyncop_how ao_how;
static int ao_how_enable = 0;
static int ao_how_enable_cb = 0;
static int ao_complete= 0;
static struct sigaction sigchld_saved_action;

static const libxl_childproc_hooks childproc_hooks = {
    .chldowner = libxl_sigchld_owner_mainloop,
    .fork_replacement = libxl_fork_replacement,
};

static virClassPtr libxlDomainObjPrivateClass;

static void
libxlDomainObjPrivateDispose(void *obj);

static void sigchld_handler(int signo)
{
    int status;
    pid_t pid;
    size_t i = 0;

    if (signo != SIGCHLD) {
        VIR_ERROR("%s: signo<%d> is not SIGCHLD", __FUNCTION__, signo);
        return;
    }
retry:
    pid = waitpid(-1, &status, WNOHANG);
    if (pid == 0) {
        VIR_INFO("%s: no child found", __FUNCTION__);
        return;
    }

    if (pid == -1) {
        if (errno == ECHILD) {
            VIR_INFO("%s: ECHILD", __FUNCTION__);
            return;
        }
        if (errno == EINTR) {
            VIR_INFO("%s: EINTR: try again", __FUNCTION__);
            goto retry;
        }
        VIR_ERROR("waitpid() failed. error: %d", errno);
        return;
    }
    //handle child reap in mainloop. because i do not have(or should not have?) ctx here.
    while(child_info.child[i].pid != pid) {
        //TODO check overflow
        i++;
    }
    child_info.child[i].pid = pid;
    child_info.child[i].status = status;
    child_info.child[i].pending = 1;
    VIR_INFO("set child pid<%d> done. status<%d>", pid, status);
}

static void
libxl_sigchld_register(void)
{
    struct sigaction ours;

    memset(&ours,0,sizeof(ours));
    ours.sa_handler = sigchld_handler;
    sigemptyset(&ours.sa_mask);
    ours.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    sigaction(SIGCHLD, &ours, &sigchld_saved_action);
}

static void
ao_how_init(libxlDomainObjPrivatePtr priv ATTRIBUTE_UNUSED, sigchild_info *info ATTRIBUTE_UNUSED)
{
    ao_complete = 0;
}

static void
ao_how_wait(libxlDriverPrivatePtr driver, virDomainObjPtr vm)
{
    VIR_INFO("Waiting for libxl event");
    size_t i;

    while (1) {
        virObjectUnlock(vm);
        libxlDriverUnlock(driver);
        sleep(1);
        libxlDriverLock(driver);
        virObjectLock(vm);
        if (ao_complete) {
            VIR_INFO("got ao_complete, exit");
            break;
        }

        i = 0;
        while(child_info.child[i].pid != 0) {
            if(child_info.child[i].pending) {
                VIR_INFO("Process child reap: pid<%d>, status<%d>", child_info.child[i].pid, child_info.child[i].status);
                libxl_childproc_reaped(child_info.ctx, child_info.child[i].pid, child_info.child[i].status);
                child_info.child[i].pending = 0;
            }

            i++;
        }
    }
}

static void
ao_how_callback(libxl_ctx *ctx ATTRIBUTE_UNUSED, int rc ATTRIBUTE_UNUSED, void *for_callback ATTRIBUTE_UNUSED)
{
    VIR_INFO("%s", __FUNCTION__);
    ao_complete=1;
    return;
}

static pid_t
libxl_fork_replacement(void *user)
{
    sigchild_info *info = user;
    pid_t pid;
    size_t i = 0;

    pid = fork();
    VIR_INFO("libxl_fork_replacement pid is %d", pid);
    if (pid > 0) {
        while(info->child[i].pid != 0) {
            //TODO check overflow
            i++;
        }
        info->child[i].pid = pid;
    }
    return pid;
}

static int
libxlDomainObjPrivateOnceInit(void)
{
    if (!(libxlDomainObjPrivateClass = virClassNew(virClassForObjectLockable(),
                                                   "libxlDomainObjPrivate",
                                                   sizeof(libxlDomainObjPrivate),
                                                   libxlDomainObjPrivateDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlDomainObjPrivate)

static void
libxlDomainObjEventHookInfoFree(void *obj)
{
    libxlEventHookInfoPtr info = obj;

    /* Drop reference on libxlDomainObjPrivate */
    virObjectUnref(info->priv);
    VIR_FREE(info);
}

static void
libxlDomainObjFDEventCallback(int watch ATTRIBUTE_UNUSED,
                              int fd,
                              int vir_events,
                              void *fd_info)
{
    libxlEventHookInfoPtr info = fd_info;
    int events = 0;

    virObjectLock(info->priv);
    if (vir_events & VIR_EVENT_HANDLE_READABLE)
        events |= POLLIN;
    if (vir_events & VIR_EVENT_HANDLE_WRITABLE)
        events |= POLLOUT;
    if (vir_events & VIR_EVENT_HANDLE_ERROR)
        events |= POLLERR;
    if (vir_events & VIR_EVENT_HANDLE_HANGUP)
        events |= POLLHUP;

    virObjectUnlock(info->priv);
    libxl_osevent_occurred_fd(info->priv->ctx, info->xl_priv, fd, 0, events);
}

static int
libxlDomainObjFDRegisterEventHook(void *priv,
                                  int fd,
                                  void **hndp,
                                  short events,
                                  void *xl_priv)
{
    int vir_events = VIR_EVENT_HANDLE_ERROR;
    libxlEventHookInfoPtr info;

    if (VIR_ALLOC(info) < 0)
        return -1;

    info->priv = priv;
    /*
     * Take a reference on the domain object.  Reference is dropped in
     * libxlDomainObjEventHookInfoFree, ensuring the domain object outlives
     * the fd event objects.
     */
    virObjectRef(info->priv);
    info->xl_priv = xl_priv;

    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    info->id = virEventAddHandle(fd, vir_events, libxlDomainObjFDEventCallback,
                                 info, libxlDomainObjEventHookInfoFree);
    if (info->id < 0) {
        virObjectUnref(info->priv);
        VIR_FREE(info);
        return -1;
    }

    *hndp = info;

    return 0;
}

static int
libxlDomainObjFDModifyEventHook(void *priv ATTRIBUTE_UNUSED,
                                int fd ATTRIBUTE_UNUSED,
                                void **hndp,
                                short events)
{
    libxlEventHookInfoPtr info = *hndp;
    int vir_events = VIR_EVENT_HANDLE_ERROR;

    virObjectLock(info->priv);
    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    virEventUpdateHandle(info->id, vir_events);
    virObjectUnlock(info->priv);

    return 0;
}

static void
libxlDomainObjFDDeregisterEventHook(void *priv ATTRIBUTE_UNUSED,
                                    int fd ATTRIBUTE_UNUSED,
                                    void *hnd)
{
    libxlEventHookInfoPtr info = hnd;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    virEventRemoveHandle(info->id);
    virObjectUnlock(p);
}

static void
libxlDomainObjTimerCallback(int timer ATTRIBUTE_UNUSED, void *timer_info)
{
    libxlEventHookInfoPtr info = timer_info;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    /*
     * libxl expects the event to be deregistered when calling
     * libxl_osevent_occurred_timeout, but we dont want the event info
     * destroyed.  Disable the timeout and only remove it after returning
     * from libxl.
     */
    virEventUpdateTimeout(info->id, -1);
    virObjectUnlock(p);
    libxl_osevent_occurred_timeout(p->ctx, info->xl_priv);
    virObjectLock(p);
    /*
     * Timeout could have been freed while the lock was dropped.
     * Only remove it from the list if it still exists.
     */
    if (virEventRemoveTimeout(info->id) == 0)
        LIBXL_EV_REG_REMOVE(p->timerRegistrations, info);
    virObjectUnlock(p);
}

static int
libxlDomainObjTimeoutRegisterEventHook(void *priv,
                                       void **hndp,
                                       struct timeval abs_t,
                                       void *xl_priv)
{
    libxlEventHookInfoPtr info;
    struct timeval now;
    struct timeval res;
    static struct timeval zero;
    int timeout;

    if (VIR_ALLOC(info) < 0)
        return -1;

    info->priv = priv;
    /*
     * Also take a reference on the domain object.  Reference is dropped in
     * libxlDomainObjEventHookInfoFree, ensuring the domain object outlives the
     * timeout event objects.
     */
    virObjectRef(info->priv);
    info->xl_priv = xl_priv;

    gettimeofday(&now, NULL);
    timersub(&abs_t, &now, &res);
    /* Ensure timeout is not overflowed */
    if (timercmp(&res, &zero, <)) {
        timeout = 0;
    } else if (res.tv_sec > INT_MAX / 1000) {
        timeout = INT_MAX;
    } else {
        timeout = res.tv_sec * 1000 + (res.tv_usec + 999) / 1000;
    }
    info->id = virEventAddTimeout(timeout, libxlDomainObjTimerCallback,
                                  info, libxlDomainObjEventHookInfoFree);
    if (info->id < 0) {
        virObjectUnref(info->priv);
        VIR_FREE(info);
        return -1;
    }

    virObjectLock(info->priv);
    LIBXL_EV_REG_APPEND(info->priv->timerRegistrations, info);
    virObjectUnlock(info->priv);
    *hndp = info;

    return 0;
}

/*
 * Note:  There are two changes wrt timeouts starting with xen-unstable
 * changeset 26469:
 *
 * 1. Timeout modify callbacks will only be invoked with an abs_t of {0,0},
 * i.e. make the timeout fire immediately.  Prior to this commit, timeout
 * modify callbacks were never invoked.
 *
 * 2. Timeout deregister hooks will no longer be called.
 */
static int
libxlDomainObjTimeoutModifyEventHook(void *priv ATTRIBUTE_UNUSED,
                                     void **hndp,
                                     struct timeval abs_t ATTRIBUTE_UNUSED)
{
    libxlEventHookInfoPtr info = *hndp;

    virObjectLock(info->priv);
    /* Make the timeout fire */
    virEventUpdateTimeout(info->id, 0);
    virObjectUnlock(info->priv);

    return 0;
}

static void
libxlDomainObjTimeoutDeregisterEventHook(void *priv ATTRIBUTE_UNUSED,
                                         void *hnd)
{
    libxlEventHookInfoPtr info = hnd;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    /*
     * Only remove the timeout from the list if removal from the
     * event loop is successful.
     */
    if (virEventRemoveTimeout(info->id) == 0)
        LIBXL_EV_REG_REMOVE(p->timerRegistrations, info);
    virObjectUnlock(p);
}


static const libxl_osevent_hooks libxl_event_callbacks = {
    .fd_register = libxlDomainObjFDRegisterEventHook,
    .fd_modify = libxlDomainObjFDModifyEventHook,
    .fd_deregister = libxlDomainObjFDDeregisterEventHook,
    .timeout_register = libxlDomainObjTimeoutRegisterEventHook,
    .timeout_modify = libxlDomainObjTimeoutModifyEventHook,
    .timeout_deregister = libxlDomainObjTimeoutDeregisterEventHook,
};

static int
libxlDomainObjInitJob(libxlDomainObjPrivatePtr priv)
{
    memset(&priv->job, 0, sizeof(priv->job));

    if (virCondInit(&priv->job.cond) < 0)
        return -1;

    return 0;
}

static void
libxlDomainObjResetJob(libxlDomainObjPrivatePtr priv)
{
    struct libxlDomainJobObj *job = &priv->job;

    job->active = LIBXL_JOB_NONE;
    job->owner = 0;
}

static void
libxlDomainObjFreeJob(libxlDomainObjPrivatePtr priv)
{
    ignore_value(virCondDestroy(&priv->job.cond));
}

/* Give up waiting for mutex after 30 seconds */
#define LIBXL_JOB_WAIT_TIME (1000ull * 30)

/*
 * obj must be locked before calling, libxlDriverPrivatePtr must NOT be locked
 *
 * This must be called by anything that will change the VM state
 * in any way
 *
 * Upon successful return, the object will have its ref count increased,
 * successful calls must be followed by EndJob eventually
 */
int
libxlDomainObjBeginJob(libxlDriverPrivatePtr driver ATTRIBUTE_UNUSED,
                       virDomainObjPtr obj,
                       enum libxlDomainJob job)
{
    libxlDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;

    if (virTimeMillisNow(&now) < 0)
        return -1;
    then = now + LIBXL_JOB_WAIT_TIME;

    virObjectRef(obj);

    while (priv->job.active) {
        VIR_DEBUG("Wait normal job condition for starting job: %s",
                  libxlDomainJobTypeToString(job));
        if (virCondWaitUntil(&priv->job.cond, &obj->parent.lock, then) < 0)
            goto error;
    }

    libxlDomainObjResetJob(priv);

    VIR_DEBUG("Starting job: %s", libxlDomainJobTypeToString(job));
    priv->job.active = job;
    priv->job.owner = virThreadSelfID();

    return 0;

error:
    VIR_WARN("Cannot start job (%s) for domain %s;"
             " current job is (%s) owned by (%d)",
             libxlDomainJobTypeToString(job),
             obj->def->name,
             libxlDomainJobTypeToString(priv->job.active),
             priv->job.owner);

    if (errno == ETIMEDOUT)
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       "%s", _("cannot acquire state change lock"));
    else
        virReportSystemError(errno,
                             "%s", _("cannot acquire job mutex"));

    virObjectUnref(obj);
    return -1;
}

/*
 * obj must be locked before calling, libxlDriverPrivatePtr does not matter
 *
 * To be called after completing the work associated with the
 * earlier libxlDomainBeginJob() call
 *
 * Returns true if the remaining reference count on obj is
 * non-zero, false if the reference count has dropped to zero
 * and obj is disposed.
 */
bool
libxlDomainObjEndJob(libxlDriverPrivatePtr driver ATTRIBUTE_UNUSED,
                     virDomainObjPtr obj)
{
    libxlDomainObjPrivatePtr priv = obj->privateData;
    enum libxlDomainJob job = priv->job.active;

    VIR_DEBUG("Stopping job: %s",
              libxlDomainJobTypeToString(job));

    libxlDomainObjResetJob(priv);
    virCondSignal(&priv->job.cond);

    return virObjectUnref(obj);
}

static void *
libxlDomainObjPrivateAlloc(void)
{
    libxlDomainObjPrivatePtr priv;

    if (libxlDomainObjPrivateInitialize() < 0)
        return NULL;

    if (!(priv = virObjectLockableNew(libxlDomainObjPrivateClass)))
        return NULL;

    if (!(priv->devs = virChrdevAlloc())) {
        virObjectUnref(priv);
        return NULL;
    }

    if (libxlDomainObjInitJob(priv) < 0) {
        virChrdevFree(priv->devs);
        virObjectUnref(priv);
        return NULL;
    }

    return priv;
}

static void
libxlDomainObjPrivateDispose(void *obj)
{
    libxlDomainObjPrivatePtr priv = obj;

    if (priv->deathW)
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);

    libxlDomainObjFreeJob(priv);
    virChrdevFree(priv->devs);

    xtl_logger_destroy(priv->logger);
    if (priv->logger_file)
        VIR_FORCE_FCLOSE(priv->logger_file);

    libxl_ctx_free(priv->ctx);
}

static void
libxlDomainObjPrivateFree(void *data)
{
    libxlDomainObjPrivatePtr priv = data;

    if (priv->deathW) {
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    virObjectUnref(priv);
}

virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks = {
    .alloc = libxlDomainObjPrivateAlloc,
    .free = libxlDomainObjPrivateFree,
};


static int
libxlDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                              virDomainDefPtr def,
                              virCapsPtr caps ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        STRNEQ(def->os.type, "hvm"))
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

    return 0;
}

virDomainDefParserConfig libxlDomainDefParserConfig = {
    .macPrefix = { 0x00, 0x16, 0x3e },
    .devicesPostParseCallback = libxlDomainDeviceDefPostParse,
};

int
libxlDomainObjPrivateInitCtx(virDomainObjPtr vm)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    char *log_file;
    int ret = -1;

    if (priv->ctx)
        return 0;

    if (virAsprintf(&log_file, "%s/%s.log", LIBXL_LOG_DIR, vm->def->name) < 0)
        return -1;

    if ((priv->logger_file = fopen(log_file, "a")) == NULL)  {
        virReportSystemError(errno,
                             _("failed to open logfile %s"),
                             log_file);
        goto cleanup;
    }

    priv->logger =
        (xentoollog_logger *)xtl_createlogger_stdiostream(priv->logger_file,
                                                          XTL_DEBUG, 0);
    if (!priv->logger) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot create libxenlight logger for domain %s"),
                       vm->def->name);
        goto cleanup;
    }

    if (libxl_ctx_alloc(&priv->ctx, LIBXL_VERSION, 0, priv->logger)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed libxl context initialization"));
        goto cleanup;
    }

    libxl_osevent_register_hooks(priv->ctx, &libxl_event_callbacks, priv);

    if (ao_how_enable) {
        if (ao_how_enable_cb)
            ao_how.callback = ao_how_callback;

        child_info.ctx = priv->ctx;
        libxl_childproc_setmode(priv->ctx, &childproc_hooks, &child_info);
        libxl_sigchld_register();
    }

    ret = 0;

cleanup:
    VIR_FREE(log_file);
    return ret;
}

void
libxlDomainObjRegisteredTimeoutsCleanup(libxlDomainObjPrivatePtr priv)
{
    libxlEventHookInfoPtr info;

    virObjectLock(priv);
    info = priv->timerRegistrations;
    while (info) {
        /*
         * libxl expects the event to be deregistered when calling
         * libxl_osevent_occurred_timeout, but we dont want the event info
         * destroyed.  Disable the timeout and only remove it after returning
         * from libxl.
         */
        virEventUpdateTimeout(info->id, -1);
        libxl_osevent_occurred_timeout(priv->ctx, info->xl_priv);
        virEventRemoveTimeout(info->id);
        info = info->next;
    }
    priv->timerRegistrations = NULL;
    virObjectUnlock(priv);
}
