/*
 * virnetsshsession.c: ssh network transport provider based on libssh2
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * Author: Peter Krempa <pkrempa@redhat.com>
 */
#include <config.h>
#include <libssh2.h>
#include <libssh2_publickey.h>

#include "virnetsshsession.h"

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virlog.h"
#include "configmake.h"
#include "virthread.h"
#include "virutil.h"
#include "virerror.h"
#include "virobject.h"

#define VIR_FROM_THIS VIR_FROM_SSH

static const char
vir_libssh2_key_comment[] = "added by libvirt ssh transport";
#define VIR_NET_SSH_BUFFER_SIZE  1024

typedef enum {
    VIR_NET_SSH_STATE_NEW,
    VIR_NET_SSH_STATE_HANDSHAKE_COMPLETE,
    VIR_NET_SSH_STATE_AUTH_CALLBACK_ERROR,
    VIR_NET_SSH_STATE_CLOSED,
    VIR_NET_SSH_STATE_ERROR,
    VIR_NET_SSH_STATE_ERROR_REMOTE,
} virNetSSHSessionState;

typedef enum {
    VIR_NET_SSH_AUTHCB_OK,
    VIR_NET_SSH_AUTHCB_NO_METHOD,
    VIR_NET_SSH_AUTHCB_OOM,
    VIR_NET_SSH_AUTHCB_RETR_ERR,
} virNetSSHAuthCallbackError;

typedef enum {
    VIR_NET_SSH_AUTH_KEYBOARD_INTERACTIVE,
    VIR_NET_SSH_AUTH_PASSWORD,
    VIR_NET_SSH_AUTH_PRIVKEY,
    VIR_NET_SSH_AUTH_AGENT
} virNetSSHAuthMethods;


typedef struct _virNetSSHAuthMethod virNetSSHAuthMethod;
typedef virNetSSHAuthMethod *virNetSSHAuthMethodPtr;

struct _virNetSSHAuthMethod {
    virNetSSHAuthMethods method;
    char *username;
    char *password;
    char *filename;

    int tries;
};

struct _virNetSSHSession {
    virObject object;
    virNetSSHSessionState state;
    virMutex lock;

    /* libssh2 internal stuff */
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_KNOWNHOSTS *knownHosts;
    LIBSSH2_AGENT *agent;

    /* for host key checking */
    virNetSSHHostkeyVerify hostKeyVerify;
    char *knownHostsFile;
    char *hostname;
    int port;

    /* authentication stuff */
    virConnectAuthPtr cred;
    virNetSSHAuthCallbackError authCbErr;
    size_t nauths;
    virNetSSHAuthMethodPtr *auths;

    /* channel stuff */
    char *channelCommand;
    int channelCommandReturnValue;

    /* read cache */
    char rbuf[VIR_NET_SSH_BUFFER_SIZE];
    size_t bufUsed;
    size_t bufStart;
};

static void
virNetSSHSessionAuthMethodsFree(virNetSSHSessionPtr sess)
{
    int i;

    for (i = 0; i < sess->nauths; i++) {
        VIR_FREE(sess->auths[i]->username);
        VIR_FREE(sess->auths[i]->password);
        VIR_FREE(sess->auths[i]->filename);
        VIR_FREE(sess->auths[i]);
    }

    VIR_FREE(sess->auths);
    sess->nauths = 0;
}

static void
virNetSSHSessionDispose(void *obj)
{
    virNetSSHSessionPtr sess = obj;
    VIR_DEBUG("sess=0x%p", sess);

    if (!sess)
        return;

    if (sess->channel) {
        libssh2_channel_send_eof(sess->channel);
        libssh2_channel_close(sess->channel);
        libssh2_channel_free(sess->channel);
    }

    libssh2_knownhost_free(sess->knownHosts);
    libssh2_agent_free(sess->agent);

    if (sess->session) {
        libssh2_session_disconnect(sess->session,
                                   "libvirt: virNetSSHSessionFree()");
        libssh2_session_free(sess->session);
    }

    virNetSSHSessionAuthMethodsFree(sess);

    VIR_FREE(sess->channelCommand);
    VIR_FREE(sess->hostname);
    VIR_FREE(sess->knownHostsFile);
}

static virClassPtr virNetSSHSessionClass;
static int
virNetSSHSessionOnceInit(void)
{
    if (!(virNetSSHSessionClass = virClassNew(virClassForObject(),
                                              "virNetSSHSession",
                                              sizeof(virNetSSHSession),
                                              virNetSSHSessionDispose)))
        return -1;

    return 0;
}
VIR_ONCE_GLOBAL_INIT(virNetSSHSession);

static virNetSSHAuthMethodPtr
virNetSSHSessionAuthMethodNew(virNetSSHSessionPtr sess)
{
    virNetSSHAuthMethodPtr auth;

    if (VIR_ALLOC(auth) < 0)
        goto error;

    if (VIR_EXPAND_N(sess->auths, sess->nauths, 1) < 0)
        goto error;

    sess->auths[sess->nauths - 1] = auth;

    return auth;

error:
    VIR_FREE(auth);
    return NULL;
}

/* keyboard interactive authentication callback */
static void
virNetSSHKbIntCb(const char *name ATTRIBUTE_UNUSED,
                 int name_len ATTRIBUTE_UNUSED,
                 const char *instruction ATTRIBUTE_UNUSED,
                 int instruction_len ATTRIBUTE_UNUSED,
                 int num_prompts,
                 const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                 LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                 void **opaque)
{
    virNetSSHSessionPtr priv = *opaque;
    virConnectCredentialPtr askcred = NULL;
    int i;
    int credtype_echo = -1;
    int credtype_noecho = -1;
    char *tmp;

    priv->authCbErr = VIR_NET_SSH_AUTHCB_OK;

    /* find credential type for asking passwords */
    for (i = 0; i < priv->cred->ncredtype; i++) {
        if (priv->cred->credtype[i] == VIR_CRED_PASSPHRASE ||
            priv->cred->credtype[i] == VIR_CRED_NOECHOPROMPT)
            credtype_noecho = priv->cred->credtype[i];

        if (priv->cred->credtype[i] == VIR_CRED_ECHOPROMPT)
            credtype_echo = priv->cred->credtype[i];
    }

    if (credtype_echo < 0 || credtype_noecho < 0) {
        priv->authCbErr = VIR_NET_SSH_AUTHCB_NO_METHOD;
        return;
    }

    if (VIR_ALLOC_N(askcred, num_prompts) < 0) {
        priv->authCbErr = VIR_NET_SSH_AUTHCB_OOM;
        return;
    }

    /* fill data structures for auth callback */
    for (i = 0; i < num_prompts; i++) {
        if (!(askcred[i].prompt = strdup(prompts[i].text))) {
            priv->authCbErr = VIR_NET_SSH_AUTHCB_OOM;
            goto cleanup;
        }

        /* remove colon and trailing spaces from prompts, as default behavior
         * of libvirt's auth callback is to add them */
        if ((tmp = strrchr(askcred[i].prompt, ':')))
            *tmp = '\0';

        askcred[i].type = prompts[i].echo ? credtype_echo : credtype_noecho;
    }

    /* retrieve responses using the auth callback */
    if (priv->cred->cb(askcred, num_prompts, priv->cred->cbdata)) {
        priv->authCbErr = VIR_NET_SSH_AUTHCB_RETR_ERR;
        goto cleanup;
    }

    /* copy retrieved data back */
    for (i = 0; i < num_prompts; i++) {
        responses[i].text = askcred[i].result;
        askcred[i].result = NULL; /* steal the pointer */
        responses[i].length = askcred[i].resultlen;
    }

cleanup:
    if (askcred) {
        for (i = 0; i < num_prompts; i++) {
            VIR_FREE(askcred[i].result);
            VIR_FREE(askcred[i].prompt);
        }
    }

    VIR_FREE(askcred);

    return;
}

/* check session host keys
 *
 * this function checks the known host database and verifies the key
 * errors are raised in this func
 *
 * return value: 0 on success, -1 on error
 */
static int
virNetSSHCheckHostKey(virNetSSHSessionPtr sess)
{
    int ret;
    const char *key;
    const char *keyhash;
    int keyType;
    size_t keyLength;
    char *errmsg;
    virBuffer buff = VIR_BUFFER_INITIALIZER;
    virConnectCredential askKey;
    struct libssh2_knownhost *knownHostEntry = NULL;
    int i;
    char *hostnameStr = NULL;

    if (sess->hostKeyVerify == VIR_NET_SSH_HOSTKEY_VERIFY_IGNORE)
        return 0;

    /* get the key */
    key = libssh2_session_hostkey(sess->session, &keyLength, &keyType);
    if (!key) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_SSH,
                       _("Failed to retrieve ssh host key: %s"),
                       errmsg);
        return -1;
    }

    /* verify it */
    ret = libssh2_knownhost_checkp(sess->knownHosts,
                                   sess->hostname,
                                   sess->port,
                                   key,
                                   keyLength,
                                   LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                                   LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                   &knownHostEntry);

    switch (ret) {
    case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
        /* key was not found, query to add it to database */
        if (sess->hostKeyVerify == VIR_NET_SSH_HOSTKEY_VERIFY_NORMAL) {
            /* ask to add the key */
            if (!sess->cred || !sess->cred->cb) {
                virReportError(VIR_ERR_SSH, "%s",
                               _("No user interaction callback provided: "
                                 "Can't verify the session host key"));
                return -1;
            }

            /* prepare data for the callback */
            memset(&askKey, 0, sizeof(virConnectCredential));

            for (i = 0; i < sess->cred->ncredtype; i++) {
                if (sess->cred->credtype[i] == VIR_CRED_ECHOPROMPT) {
                    i = -1;
                    break;
                }
            }

            if (i > 0) {
                virReportError(VIR_ERR_SSH, "%s",
                               _("no suitable method to retrieve "
                                 "authentication credentials"));
                return -1;
            }

            /* calculate remote key hash, using MD5 algorithm that is
             * usual in OpenSSH. The returned value should *NOT* be freed*/
            if (!(keyhash = libssh2_hostkey_hash(sess->session,
                                                 LIBSSH2_HOSTKEY_HASH_MD5))) {
                virReportError(VIR_ERR_SSH, "%s",
                               _("failed to calculate ssh host key hash"));
                return -1;
            }
            /* format the host key into a nice userfriendly string.
             * Sadly, there's no constant to describe the hash length, so
             * we have to use a *MAGIC* constant. */
            for (i = 0; i < 16; i++)
                    virBufferAsprintf(&buff, "%02hhX:", keyhash[i]);
            virBufferTrim(&buff, ":", 1);

            if (virBufferError(&buff) != 0) {
                virReportOOMError();
                return -1;
            }

            keyhash = virBufferContentAndReset(&buff);

            askKey.type = VIR_CRED_ECHOPROMPT;
            if (virAsprintf((char **)&askKey.prompt,
                            _("Accept SSH host key with hash '%s' for "
                              "host '%s:%d' (%s/%s)?"),
                            keyhash,
                            sess->hostname, sess->port,
                            "y", "n") < 0) {
                virReportOOMError();
                VIR_FREE(keyhash);
                return -1;
            }

            if (sess->cred->cb(&askKey, 1, sess->cred->cbdata)) {
                virReportError(VIR_ERR_SSH, "%s",
                               _("failed to retrieve decision to accept "
                                 "host key"));
                VIR_FREE(askKey.prompt);
                VIR_FREE(keyhash);
                return -1;
            }

            VIR_FREE(askKey.prompt);

            if (!askKey.result ||
                STRCASENEQ(askKey.result, "y")) {
                virReportError(VIR_ERR_SSH,
                               _("SSH host key for '%s' (%s) was not accepted"),
                               sess->hostname, keyhash);
                VIR_FREE(keyhash);
                VIR_FREE(askKey.result);
                return -1;
            }
            VIR_FREE(keyhash);
            VIR_FREE(askKey.result);
        }

        /* VIR_NET_SSH_HOSTKEY_VERIFY_AUTO_ADD */
        /* convert key type, as libssh is using different enums type for
         * getting the key and different for adding ... */
        switch (keyType) {
        case LIBSSH2_HOSTKEY_TYPE_RSA:
            keyType = LIBSSH2_KNOWNHOST_KEY_SSHRSA;
            break;
        case LIBSSH2_HOSTKEY_TYPE_DSS:
            keyType = LIBSSH2_KNOWNHOST_KEY_SSHDSS;
            break;

        case LIBSSH2_HOSTKEY_TYPE_UNKNOWN:
        default:
            virReportError(VIR_ERR_SSH, "%s",
                           _("unsupported SSH key type"));
            return -1;
        }

        /* add the key to the DB and save it, if applicable */
        /* construct a "[hostname]:port" string to have the hostkey bound
         * to port number */
        virBufferAsprintf(&buff, "[%s]:%d", sess->hostname, sess->port);

        if (virBufferError(&buff) != 0) {
            virReportOOMError();
            return -1;
        }

        hostnameStr = virBufferContentAndReset(&buff);

        if (libssh2_knownhost_addc(sess->knownHosts,
                                   hostnameStr,
                                   NULL,
                                   key,
                                   keyLength,
                                   vir_libssh2_key_comment,
                                   strlen(vir_libssh2_key_comment),
                                   LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                                   LIBSSH2_KNOWNHOST_KEYENC_RAW |
                                   keyType,
                                   NULL) < 0) {
            libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
            virReportError(VIR_ERR_SSH,
                           _("unable to add SSH host key for host '%s': %s"),
                           hostnameStr, errmsg);
            VIR_FREE(hostnameStr);
            return -1;
        }

        VIR_FREE(hostnameStr);

        /* write the host key file - if applicable */
        if (sess->knownHostsFile) {
            if (libssh2_knownhost_writefile(sess->knownHosts,
                                            sess->knownHostsFile,
                                         LIBSSH2_KNOWNHOST_FILE_OPENSSH) < 0) {
                libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
                virReportError(VIR_ERR_SSH,
                               _("failed to write known_host file '%s': %s"),
                               sess->knownHostsFile,
                               errmsg);
                return -1;
            }
        }
        /* key was accepted and added */
        return 0;

    case LIBSSH2_KNOWNHOST_CHECK_MATCH:
        /* host key matches */
        return 0;

    case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
        /* host key verification failed */
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("!!! SSH HOST KEY VERIFICATION FAILED !!!: "
                         "Identity of host '%s:%d' differs from stored identity. "
                         "Please verify the new host key '%s' to avoid possible "
                         "man in the middle attack. The key is stored in '%s'."),
                       sess->hostname, sess->port,
                       knownHostEntry->key, sess->knownHostsFile);
        return -1;

    case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_SSH,
                       _("failed to validate SSH host key: %s"),
                       errmsg);
        return -1;

    default: /* should never happen (tm) */
        virReportError(VIR_ERR_SSH, "%s", _("Unknown error value"));
        return -1;
    }

    return -1;
}

/* perform ssh agent authentication
 *
 * Returns: 0 on success
 *          1 on authentication failure
 *         -1 on error
 */
static int
virNetSSHAuthenticateAgent(virNetSSHSessionPtr sess,
                           virNetSSHAuthMethodPtr priv)
{
    struct libssh2_agent_publickey *agent_identity = NULL;
    bool no_identity = true;
    int ret;
    char *errmsg;

    if (libssh2_agent_connect(sess->agent) < 0) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to connect to ssh agent"));
        return 1;
    }

    if (libssh2_agent_list_identities(sess->agent) < 0) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to list ssh agent identities"));
        return 1;
    }

    while (!(ret = libssh2_agent_get_identity(sess->agent,
                                              &agent_identity,
                                              agent_identity))) {
        no_identity = false;
        if (!(ret = libssh2_agent_userauth(sess->agent,
                                           priv->username,
                                           agent_identity)))
            return 0; /* key accepted */

        if (ret != LIBSSH2_ERROR_AUTHENTICATION_FAILED &&
            ret != LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED &&
            ret != LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) {
            libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("failed to authenticate using SSH agent: %s"),
                           errmsg);
            return -1;
        }
        /* authentication has failed, try next key */
    }

    /* if there are no more keys in the agent, the identity retrieval
     * function returns 1 */
    if (ret == 1) {
        if (no_identity) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("SSH Agent did not provide any "
                             "authentication identity"));
        } else {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("All identities provided by the SSH Agent "
                             "were rejected"));
        }
        return 1;
    }

    libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
    virReportError(VIR_ERR_AUTH_FAILED,
                   _("failed to authenticate using SSH agent: %s"),
                   errmsg);
    return -1;
}

/* perform private key authentication
 *
 * Returns: 0 on success
 *          1 on authentication failure
 *         -1 on error
 */
static int
virNetSSHAuthenticatePrivkey(virNetSSHSessionPtr sess,
                             virNetSSHAuthMethodPtr priv)
{
    virConnectCredential retr_passphrase;
    int i;
    char *errmsg;
    int ret;

    /* try open the key with no password */
    if ((ret = libssh2_userauth_publickey_fromfile(sess->session,
                                                   priv->username,
                                                   NULL,
                                                   priv->filename,
                                                   priv->password)) == 0)
        return 0; /* success */

    if (priv->password ||
        ret == LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED ||
        ret == LIBSSH2_ERROR_AUTHENTICATION_FAILED) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("authentication with private key '%s' "
                         "has failed: %s"),
                       priv->filename, errmsg);
        return 1; /* auth failed */
    }

    /* request user's key password */
    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("No user interaction callback provided: "
                         "Can't retrieve private key passphrase"));
        return -1;
    }

    memset(&retr_passphrase, 0, sizeof(virConnectCredential));
    retr_passphrase.type = -1;

    for (i = 0; i < sess->cred->ncredtype; i++) {
        if (sess->cred->credtype[i] == VIR_CRED_PASSPHRASE ||
            sess->cred->credtype[i] == VIR_CRED_NOECHOPROMPT) {
            retr_passphrase.type = sess->cred->credtype[i];
            break;
        }
    }

    if (retr_passphrase.type < 0) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("no suitable method to retrieve key passphrase"));
        return -1;
    }

    if (virAsprintf((char **)&retr_passphrase.prompt,
                    _("Passphrase for key '%s'"),
                    priv->filename) < 0) {
        virReportOOMError();
        return -1;
    }

    if (sess->cred->cb(&retr_passphrase, 1, sess->cred->cbdata)) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("failed to retrieve private key passphrase: "
                         "callback has failed"));
        VIR_FREE(retr_passphrase.prompt);
        return -1;
    }

    VIR_FREE(retr_passphrase.prompt);

    ret = libssh2_userauth_publickey_fromfile(sess->session,
                                              priv->username,
                                              NULL,
                                              priv->filename,
                                              retr_passphrase.result);

    VIR_FREE(retr_passphrase.result);

    if (ret < 0) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("authentication with private key '%s' "
                         "has failed: %s"),
                       priv->filename, errmsg);

        if (ret == LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED ||
            ret == LIBSSH2_ERROR_AUTHENTICATION_FAILED)
            return 1;
        else
            return -1;
    }

    return 0;
}

/* perform tunelled password authentication
 *
 * Returns: 0 on success
 *          1 on authentication failure
 *         -1 on error
 */
static int
virNetSSHAuthenticatePassword(virNetSSHSessionPtr sess,
                              virNetSSHAuthMethodPtr priv)
{
    char *errmsg;
    int ret;

    /* tunelled password authentication */
    if ((ret = libssh2_userauth_password(sess->session,
                                         priv->username,
                                         priv->password)) < 0) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("tunelled password authentication failed: %s"),
                       errmsg);

        if (ret == LIBSSH2_ERROR_AUTHENTICATION_FAILED)
            return 1;
        else
            return -1;
    }
    /* auth success */
    return 0;
}

/* perform keyboard interactive authentication
 *
 * Returns: 0 on success
 *          1 on authentication failure
 *         -1 on error
 */
static int
virNetSSHAuthenticateKeyboardInteractive(virNetSSHSessionPtr sess,
                                         virNetSSHAuthMethodPtr priv)
{
    char *errmsg;
    int ret;

    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Can't perform keyboard-interactive authentication: "
                         "Authentication callback not provided "));
        return -1;
    }

    /* Try the authenticating the set amount of times. The server breaks the
     * connection if maximum number of bad auth tries is exceeded */
    while (priv->tries < 0 || priv->tries-- > 0) {
        ret = libssh2_userauth_keyboard_interactive(sess->session,
                                                    priv->username,
                                                    virNetSSHKbIntCb);

        /* check for errors while calling the callback */
        switch (sess->authCbErr) {
        case VIR_NET_SSH_AUTHCB_NO_METHOD:
            virReportError(VIR_ERR_SSH, "%s",
                           _("no suitable method to retrieve "
                             "authentication credentials"));
            return -1;
        case VIR_NET_SSH_AUTHCB_OOM:
            virReportOOMError();
            return -1;
        case VIR_NET_SSH_AUTHCB_RETR_ERR:
            virReportError(VIR_ERR_SSH, "%s",
                           _("failed to retrieve credentials"));
            return -1;
        case VIR_NET_SSH_AUTHCB_OK:
            /* everything went fine, let's continue */
            break;
        }

        if (ret == 0)
            /* authentication succeeded */
            return 0;

        if (ret == LIBSSH2_ERROR_AUTHENTICATION_FAILED)
            continue; /* try again */

        if (ret < 0) {
            libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("keyboard interactive authentication failed: %s"),
                           errmsg);
            return -1;
        }
    }
    libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
    virReportError(VIR_ERR_AUTH_FAILED,
                   _("keyboard interactive authentication failed: %s"),
                   errmsg);
    return 1;
}

/* select auth method and authenticate */
static int
virNetSSHAuthenticate(virNetSSHSessionPtr sess)
{
    virNetSSHAuthMethodPtr auth;
    bool no_method = false;
    bool auth_failed = false;
    char *auth_list;
    char *errmsg;
    int i;
    int ret;

    if (!sess->nauths) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("No authentication methods and credentials "
                         "provided"));
        return -1;
    }

    /* obtain list of supported auth methods */
    auth_list = libssh2_userauth_list(sess->session,
                                      sess->auths[0]->username,
                                      strlen(sess->auths[0]->username));
    if (!auth_list) {
        /* unlikely event, authentication succeeded with NONE as method */
        if (libssh2_userauth_authenticated(sess->session) == 1)
            return 0;

        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_SSH,
                       _("couldn't retrieve authentication methods list: %s"),
                       errmsg);
        return -1;
    }

    for (i = 0; i < sess->nauths; i++) {
        auth = sess->auths[i];

        ret = 2;
        virResetLastError();

        switch (auth->method) {
        case VIR_NET_SSH_AUTH_KEYBOARD_INTERACTIVE:
            if (strstr(auth_list, "keyboard-interactive"))
                ret = virNetSSHAuthenticateKeyboardInteractive(sess, auth);
            break;
        case VIR_NET_SSH_AUTH_AGENT:
            if (strstr(auth_list, "publickey"))
                ret = virNetSSHAuthenticateAgent(sess, auth);
            break;
        case VIR_NET_SSH_AUTH_PRIVKEY:
            if (strstr(auth_list, "publickey"))
                ret = virNetSSHAuthenticatePrivkey(sess, auth);
            break;
        case VIR_NET_SSH_AUTH_PASSWORD:
            if (strstr(auth_list, "password"))
                ret = virNetSSHAuthenticatePassword(sess, auth);
            break;
        }

        /* return on success or error */
        if (ret <= 0)
            return ret;

        /* the authentication method is not supported */
        if (ret == 2)
            no_method = true;

        /* authentication with this method has failed */
        if (ret == 1)
            auth_failed = true;
    }

    if (sess->nauths == 0) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("No authentication methods supplied"));
    } else if (sess->nauths == 1) {
        /* pass through the error */
    } else if (no_method && !auth_failed) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("None of the requested authentication methods "
                         "are supported by the server"));
    } else {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("All provided authentication methods with credentials "
                         "were rejected by the server"));
    }

    return -1;
}

/* open channel */
static int
virNetSSHOpenChannel(virNetSSHSessionPtr sess)
{
    char *errmsg;

    sess->channel = libssh2_channel_open_session(sess->session);
    if (!sess->channel) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_SSH,
                       _("failed to open ssh channel: %s"),
                       errmsg);
        return -1;
    }

    if (libssh2_channel_exec(sess->channel, sess->channelCommand) != 0) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_SSH,
                       _("failed to execute command '%s': %s"),
                       sess->channelCommand,
                       errmsg);
        return -1;
    }

    /* nonblocking mode - currently does nothing*/
    libssh2_channel_set_blocking(sess->channel, 0);

    /* channel open */
    return 0;
}

/* validate if all required parameters are configured */
static int
virNetSSHValidateConfig(virNetSSHSessionPtr sess)
{
    if (sess->nauths == 0) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("No authentication methods and credentials "
                         "provided"));
        return -1;
    }

    if (!sess->channelCommand) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("No channel command provided"));
        return -1;
    }

    if (sess->hostKeyVerify != VIR_NET_SSH_HOSTKEY_VERIFY_IGNORE) {
        if (!sess->hostname) {
            virReportError(VIR_ERR_SSH, "%s",
                           _("Hostname is needed for host key verification"));
            return -1;
        }
    }

    /* everything ok */
    return 0;
}

/* ### PUBLIC API ### */
int
virNetSSHSessionAuthSetCallback(virNetSSHSessionPtr sess,
                                virConnectAuthPtr auth)
{
    virMutexLock(&sess->lock);
    sess->cred = auth;
    virMutexUnlock(&sess->lock);
    return 0;
}

void
virNetSSHSessionAuthReset(virNetSSHSessionPtr sess)
{
    virMutexLock(&sess->lock);
    virNetSSHSessionAuthMethodsFree(sess);
    virMutexUnlock(&sess->lock);
}

int
virNetSSHSessionAuthAddPasswordAuth(virNetSSHSessionPtr sess,
                                    const char *username,
                                    const char *password)
{
    virNetSSHAuthMethodPtr auth;
    char *user = NULL;
    char *pass = NULL;

    if (!username || !password) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Username and password must be provided "
                         "for password authentication"));
        return -1;
    }

    virMutexLock(&sess->lock);

    if (!(user = strdup(username)) ||
        !(pass = strdup(password)))
        goto no_memory;

    if (!(auth = virNetSSHSessionAuthMethodNew(sess)))
        goto no_memory;

    auth->username = user;
    auth->password = pass;
    auth->method = VIR_NET_SSH_AUTH_PASSWORD;

    virMutexUnlock(&sess->lock);
    return 0;

no_memory:
    VIR_FREE(user);
    VIR_FREE(pass);
    virReportOOMError();
    virMutexUnlock(&sess->lock);
    return -1;
}

int
virNetSSHSessionAuthAddAgentAuth(virNetSSHSessionPtr sess,
                                 const char *username)
{
    virNetSSHAuthMethodPtr auth;
    char *user = NULL;

    if (!username) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Username must be provided "
                         "for ssh agent authentication"));
        return -1;
    }

    virMutexLock(&sess->lock);

    if (!(user = strdup(username)))
        goto no_memory;

    if (!(auth = virNetSSHSessionAuthMethodNew(sess)))
        goto no_memory;

    auth->username = user;
    auth->method = VIR_NET_SSH_AUTH_AGENT;

    virMutexUnlock(&sess->lock);
    return 0;

no_memory:
    VIR_FREE(user);
    virReportOOMError();
    virMutexUnlock(&sess->lock);
    return -1;
}

int
virNetSSHSessionAuthAddPrivKeyAuth(virNetSSHSessionPtr sess,
                                   const char *username,
                                   const char *keyfile,
                                   const char *password)
{
    virNetSSHAuthMethodPtr auth;

    char *user = NULL;
    char *pass = NULL;
    char *file = NULL;

    if (!username || !keyfile) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Username and key file path must be provided "
                         "for private key authentication"));
        return -1;
    }

    virMutexLock(&sess->lock);

    if (!(user = strdup(username)) ||
        !(file = strdup(keyfile)))
        goto no_memory;

    if (password && !(pass = strdup(password)))
        goto no_memory;

    if (!(auth = virNetSSHSessionAuthMethodNew(sess)))
        goto no_memory;

    auth->username = user;
    auth->password = pass;
    auth->filename = file;
    auth->method = VIR_NET_SSH_AUTH_PRIVKEY;

    virMutexUnlock(&sess->lock);
    return 0;

no_memory:
    VIR_FREE(user);
    VIR_FREE(pass);
    VIR_FREE(file);
    virReportOOMError();
    virMutexUnlock(&sess->lock);
    return -1;
}

int
virNetSSHSessionAuthAddKeyboardAuth(virNetSSHSessionPtr sess,
                                    const char *username,
                                    int tries)
{
    virNetSSHAuthMethodPtr auth;
    char *user = NULL;

    if (!username) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Username must be provided "
                         "for ssh agent authentication"));
        return -1;
    }

    virMutexLock(&sess->lock);

    if (!(user = strdup(username)))
        goto no_memory;

    if (!(auth = virNetSSHSessionAuthMethodNew(sess)))
        goto no_memory;

    auth->username = user;
    auth->tries = tries;
    auth->method = VIR_NET_SSH_AUTH_KEYBOARD_INTERACTIVE;

    virMutexUnlock(&sess->lock);
    return 0;

no_memory:
    VIR_FREE(user);
    virReportOOMError();
    virMutexUnlock(&sess->lock);
    return -1;

}

int
virNetSSHSessionSetChannelCommand(virNetSSHSessionPtr sess,
                                  const char *command)
{
    int ret = 0;
    virMutexLock(&sess->lock);

    VIR_FREE(sess->channelCommand);

    if (command && !(sess->channelCommand = strdup(command))) {
        virReportOOMError();
        ret = -1;
    }

    virMutexUnlock(&sess->lock);
    return ret;
}

int
virNetSSHSessionSetHostKeyVerification(virNetSSHSessionPtr sess,
                                       const char *hostname,
                                       int port,
                                       const char *hostsfile,
                                       virNetSSHHostkeyVerify opt,
                                       unsigned int flags)
{
    char *errmsg;

    virMutexLock(&sess->lock);

    sess->port = port;
    sess->hostKeyVerify = opt;

    VIR_FREE(sess->hostname);

    if (hostname && !(sess->hostname = strdup(hostname)))
        goto no_memory;

    /* load the known hosts file */
    if (hostsfile) {
        if (virFileExists(hostsfile)) {
            if (libssh2_knownhost_readfile(sess->knownHosts,
                                           hostsfile,
                                           LIBSSH2_KNOWNHOST_FILE_OPENSSH) < 0) {
                libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
                virReportError(VIR_ERR_SSH,
                               _("unable to load knownhosts file '%s': %s"),
                               hostsfile, errmsg);
                goto error;
            }
        } else if (!(flags & VIR_NET_SSH_HOSTKEY_FILE_CREATE)) {
            virReportError(VIR_ERR_SSH,
                           _("known hosts file '%s' does not exist"),
                           hostsfile);
            goto error;
        }

        /* set filename only if writing to the known hosts file is requested */
        if (!(flags & VIR_NET_SSH_HOSTKEY_FILE_READONLY)) {
            VIR_FREE(sess->knownHostsFile);
            if (!(sess->knownHostsFile = strdup(hostsfile)))
                goto no_memory;
        }
    }

    virMutexUnlock(&sess->lock);
    return 0;

no_memory:
    virReportOOMError();
error:
    virMutexUnlock(&sess->lock);
    return -1;
}

/* allocate and initialize a ssh session object */
virNetSSHSessionPtr virNetSSHSessionNew(void)
{
    virNetSSHSessionPtr sess = NULL;

    if (virNetSSHSessionInitialize() < 0)
        goto error;

    if (!(sess = virObjectNew(virNetSSHSessionClass)))
        goto error;

    /* initialize internal structures */
    if (virMutexInit(&sess->lock) < 0) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to initialize mutex"));
        goto error;
    }

    /* initialize session data, use the internal data for callbacks
     * and stick to default memory management functions */
    if (!(sess->session = libssh2_session_init_ex(NULL,
                                                  NULL,
                                                  NULL,
                                                  (void *)sess))) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to initialize libssh2 session"));
        goto error;
    }

    if (!(sess->knownHosts = libssh2_knownhost_init(sess->session))) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to initialize libssh2 known hosts table"));
        goto error;
    }

    if (!(sess->agent = libssh2_agent_init(sess->session))) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to initialize libssh2 agent handle"));
        goto error;
    }

    VIR_DEBUG("virNetSSHSessionPtr: %p, LIBSSH2_SESSION: %p",
              sess, sess->session);

    /* set blocking mode for libssh2 until handshake is complete */
    libssh2_session_set_blocking(sess->session, 1);

    /* default states for config variables */
    sess->state = VIR_NET_SSH_STATE_NEW;
    sess->hostKeyVerify = VIR_NET_SSH_HOSTKEY_VERIFY_IGNORE;

    return sess;

error:
    virObjectUnref(sess);
    return NULL;
}

int
virNetSSHSessionConnect(virNetSSHSessionPtr sess,
                        int sock)
{
    int ret;
    char *errmsg;

    VIR_DEBUG("sess=%p, sock=%d", sess, sock);

    if (!sess || sess->state != VIR_NET_SSH_STATE_NEW) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Invalid virNetSSHSessionPtr"));
        return -1;
    }

    virMutexLock(&sess->lock);

    /* check if configuration is valid */
    if ((ret = virNetSSHValidateConfig(sess)) < 0)
        goto error;

    /* open session */
    ret = libssh2_session_handshake(sess->session, sock);
    /* libssh2 is in blocking mode, so EAGAIN will never happen */
    if (ret < 0) {
        libssh2_session_last_error(sess->session, &errmsg, NULL, 0);
        virReportError(VIR_ERR_NO_CONNECT,
                       _("SSH session handshake failed: %s"),
                       errmsg);
        goto error;
    }

    /* verify the SSH host key */
    if ((ret = virNetSSHCheckHostKey(sess)) != 0)
        goto error;

    /* authenticate */
    if ((ret = virNetSSHAuthenticate(sess)) != 0)
        goto error;

    /* open channel */
    if ((ret = virNetSSHOpenChannel(sess)) != 0)
        goto error;

    /* all set */
    /* switch to nonblocking mode and return */
    libssh2_session_set_blocking(sess->session, 0);
    sess->state = VIR_NET_SSH_STATE_HANDSHAKE_COMPLETE;

    virMutexUnlock(&sess->lock);
    return ret;

error:
    sess->state = VIR_NET_SSH_STATE_ERROR;
    virMutexUnlock(&sess->lock);
    return ret;
}

/* do a read from a ssh channel, used instead of normal read on socket */
ssize_t
virNetSSHChannelRead(virNetSSHSessionPtr sess,
                     char *buf,
                     size_t len)
{
    ssize_t ret = -1;
    ssize_t read_n = 0;

    virMutexLock(&sess->lock);

    if (sess->state != VIR_NET_SSH_STATE_HANDSHAKE_COMPLETE) {
        if (sess->state == VIR_NET_SSH_STATE_ERROR_REMOTE)
            virReportError(VIR_ERR_SSH,
                           _("Remote program terminated "
                             "with non-zero code: %d"),
                           sess->channelCommandReturnValue);
        else
            virReportError(VIR_ERR_SSH, "%s",
                           _("Tried to write socket in error state"));

        virMutexUnlock(&sess->lock);
        return -1;
    }

    if (sess->bufUsed > 0) {
        /* copy the rest (or complete) internal buffer to the output buffer */
        memcpy(buf,
               sess->rbuf + sess->bufStart,
               len > sess->bufUsed ? sess->bufUsed : len);

        if (len >= sess->bufUsed) {
            read_n = sess->bufUsed;

            sess->bufStart = 0;
            sess->bufUsed = 0;
        } else {
            read_n = len;
            sess->bufUsed -= len;
            sess->bufStart += len;

            goto success;
        }
    }

    /* continue reading into the buffer supplied */
    if (read_n < len) {
        ret = libssh2_channel_read(sess->channel,
                                   buf + read_n,
                                   len - read_n);

        if (ret == LIBSSH2_ERROR_EAGAIN)
            goto success;

        if (ret < 0)
            goto error;

        read_n += ret;
    }

    /* try to read something into the internal buffer */
    if (sess->bufUsed == 0) {
        ret = libssh2_channel_read(sess->channel,
                                   sess->rbuf,
                                   VIR_NET_SSH_BUFFER_SIZE);

        if (ret == LIBSSH2_ERROR_EAGAIN)
            goto success;

        if (ret < 0)
            goto error;

        sess->bufUsed = ret;
        sess->bufStart = 0;
    }

    if (read_n == 0) {
        /* get rid of data in stderr stream */
        ret = libssh2_channel_read_stderr(sess->channel,
                                          sess->rbuf,
                                          VIR_NET_SSH_BUFFER_SIZE - 1);
        if (ret > 0) {
            sess->rbuf[ret] = '\0';
            VIR_DEBUG("flushing stderr, data='%s'",  sess->rbuf);
        }
    }

    if (libssh2_channel_eof(sess->channel)) {
        if (libssh2_channel_get_exit_status(sess->channel)) {
            virReportError(VIR_ERR_SSH,
                           _("Remote command terminated with non-zero code: %d"),
                           libssh2_channel_get_exit_status(sess->channel));
            sess->channelCommandReturnValue = libssh2_channel_get_exit_status(sess->channel);
            sess->state = VIR_NET_SSH_STATE_ERROR_REMOTE;
            virMutexUnlock(&sess->lock);
            return -1;
        }

        sess->state = VIR_NET_SSH_STATE_CLOSED;
        virMutexUnlock(&sess->lock);
        return -1;
    }

success:
    virMutexUnlock(&sess->lock);
    return read_n;

error:
    sess->state = VIR_NET_SSH_STATE_ERROR;
    virMutexUnlock(&sess->lock);
    return ret;
}

ssize_t
virNetSSHChannelWrite(virNetSSHSessionPtr sess,
                      const char *buf,
                      size_t len)
{
    ssize_t ret;

    virMutexLock(&sess->lock);

    if (sess->state != VIR_NET_SSH_STATE_HANDSHAKE_COMPLETE) {
        if (sess->state == VIR_NET_SSH_STATE_ERROR_REMOTE)
            virReportError(VIR_ERR_SSH,
                           _("Remote program terminated with non-zero code: %d"),
                           sess->channelCommandReturnValue);
        else
            virReportError(VIR_ERR_SSH, "%s",
                           _("Tried to write socket in error state"));
        ret = -1;
        goto cleanup;
    }

    if (libssh2_channel_eof(sess->channel)) {
        if (libssh2_channel_get_exit_status(sess->channel)) {
            virReportError(VIR_ERR_SSH,
                           _("Remote program terminated with non-zero code: %d"),
                           libssh2_channel_get_exit_status(sess->channel));
            sess->state = VIR_NET_SSH_STATE_ERROR_REMOTE;
            sess->channelCommandReturnValue = libssh2_channel_get_exit_status(sess->channel);

            ret = -1;
            goto cleanup;
        }

        sess->state = VIR_NET_SSH_STATE_CLOSED;
        ret = -1;
        goto cleanup;
    }

    ret = libssh2_channel_write(sess->channel, buf, len);
    if (ret == LIBSSH2_ERROR_EAGAIN) {
        ret = 0;
        goto cleanup;
    }

    if (ret < 0) {
        char *msg;
        sess->state = VIR_NET_SSH_STATE_ERROR;
        libssh2_session_last_error(sess->session, &msg, NULL, 0);
        virReportError(VIR_ERR_SSH,
                       _("write failed: %s"), msg);
    }

cleanup:
    virMutexUnlock(&sess->lock);
    return ret;
}

bool
virNetSSHSessionHasCachedData(virNetSSHSessionPtr sess)
{
    bool ret;

    if (!sess)
        return false;

    virMutexLock(&sess->lock);

    ret = sess->bufUsed > 0;

    virMutexUnlock(&sess->lock);
    return ret;
}
