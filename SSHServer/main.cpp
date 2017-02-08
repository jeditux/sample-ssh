#include <iostream>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <stdlib.h>
#include <stdio.h>

using namespace std;

#define KEYSFOLDER
#define USER       "bob"
#define PASSWORD   "mypass"

static int authentificated = 0;
static ssh_channel channel = NULL;
static int error = 0;
int port = 10022;
ssh_channel_callbacks_struct channel_cb;

static int pty_request(ssh_session session, ssh_channel channel, const char *term,
        int x,int y, int px, int py, void *userdata){
    (void) session;
    (void) channel;
    (void) term;
    (void) x;
    (void) y;
    (void) px;
    (void) py;
    (void) userdata;
    printf("Allocated terminal\n");
    return 0;
}

static int shell_request(ssh_session session, ssh_channel channel, void *userdata){
    (void)session;
    (void)channel;
    (void)userdata;
    printf("Allocated shell\n");
    return 0;
}

static int auth_pubkey(ssh_session session, const char* user, struct ssh_key_struct* pubkey,
                       char signature_state, void* userdata){
    ssh_key key;
    int r = ssh_pki_import_pubkey_file("./id_rsa.pub", &key);
    if(r != SSH_OK){
        printf("Error importing the public key: %s\n", ssh_get_error(session));
        return SSH_AUTH_DENIED;
    }
    if(signature_state == SSH_PUBLICKEY_STATE_NONE){
        printf("STATE_NONE\n");
        if(ssh_key_cmp(pubkey, key, SSH_KEY_CMP_PUBLIC) == 0){
            printf("Key match\n");
            ssh_key_free(key);
            return SSH_AUTH_SUCCESS;
        }
    }
    else if(signature_state == SSH_PUBLICKEY_STATE_VALID){
        printf("STATE_VALID\n");
        authentificated = 1;
        ssh_key_free(key);
        return SSH_AUTH_SUCCESS;
    }
    ssh_key_free(key);
    return SSH_AUTH_DENIED;
}

static int auth_password(ssh_session session, const char* user, const char* password, void* userdata){
    printf("Authentification user %s with password %s\n", user, password);
    if(strcmp(user, USER) == 0 && strcmp(password, PASSWORD) == 0){
        authentificated = 1;
        printf("Authentificated\n");
        return SSH_AUTH_SUCCESS;
    }
    return SSH_AUTH_DENIED;
}

static ssh_channel new_session_channel(ssh_session session, void *userdata){
    (void) session;
    (void) userdata;
    if(channel != NULL)
        return NULL;
    printf("Allocated session channel\n");
    channel = ssh_channel_new(session);
    channel_cb.channel_auth_agent_req_function = NULL;
    channel_cb.channel_close_function = NULL;
    channel_cb.channel_data_function = NULL;
    channel_cb.channel_env_request_function = NULL;
    channel_cb.channel_eof_function = NULL;
    channel_cb.channel_exec_request_function = NULL;
    channel_cb.channel_exit_signal_function = NULL;
    channel_cb.channel_exit_status_function = NULL;
    channel_cb.channel_pty_request_function = pty_request;
    channel_cb.channel_pty_window_change_function = NULL;
    channel_cb.channel_shell_request_function = shell_request;
    channel_cb.channel_signal_function = NULL;
    channel_cb.channel_subsystem_request_function = NULL;
    channel_cb.channel_x11_req_function = NULL;
    channel_cb.size = 0;
    channel_cb.userdata = NULL;
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(channel, &channel_cb);
    return channel;
}

int main()
{
    ssh_session session;
    ssh_bind sshbind;
    ssh_message message;
    int verbosity = SSH_LOG_PROTOCOL;
    ssh_server_callbacks_struct cb;
    cb.auth_gssapi_mic_function = NULL;
    cb.auth_none_function = NULL;
    cb.auth_password_function = auth_password;
    cb.auth_pubkey_function = auth_pubkey;
    cb.channel_open_request_session_function = new_session_channel;
    cb.gssapi_accept_sec_ctx_function = NULL;
    cb.gssapi_select_oid_function = NULL;
    cb.gssapi_verify_mic_function = NULL;
    cb.service_request_function = NULL;
    cb.size = 0;
    cb.userdata = NULL;

    sshbind = ssh_bind_new();
    session = ssh_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "./ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "./ssh_host_rsa_key");

    if(ssh_bind_listen(sshbind) < 0){
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    printf("Waiting for connection...\n");
    int r = ssh_bind_accept(sshbind, session);
    if(r == SSH_ERROR){
        printf("Error accepting a connection: %s\n", ssh_get_error(sshbind));
        return 1;
    }
    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(session, &cb);
    if(ssh_handle_key_exchange(session)){
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
    ssh_event mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, session);

    while(!(authentificated && channel != NULL)){
        if(error)
            break;
        r = ssh_event_dopoll(mainloop, -1);
        if(r == SSH_ERROR){
            printf("Error: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            return 1;
        }
    }
    if(error)
        printf("Error, exiting loop\n");
    else
        printf("Authentificated and got a channel\n");
    int i;
    char buf[2048];
    do{
        i = ssh_channel_read(channel, buf, 2048, 0);
        if(i>0){
            ssh_channel_write(channel, buf, i);
            if(write(1, buf, i) < 0){
                printf("Error writing to buffer\n");
                return 1;
            }
            if (buf[0] == '\x0d') {
                if (write(1, "\n", 1) < 0) {
                    printf("error writing to buffer\n");
                    return 1;
                }
                ssh_channel_write(channel, "\n", 1);
            }
        }
    }
    while(i>0);

    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
