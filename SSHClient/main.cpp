#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
//#include <conio.h>
#include <string>
#include <iostream>

using namespace std;

int main()
{
    ssh_session session = ssh_new();
    int verbosity = SSH_LOG_PROTOCOL;
    int port = 10022;
    if(session == NULL)
        return 1;
    ssh_options_set(session, SSH_OPTIONS_HOST, "127.0.0.1");
    ssh_options_set(session, SSH_OPTIONS_USER, "bob");
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    int r = ssh_connect(session);
    if(r != SSH_OK){
        printf("Error connecting to localhost: %s\n", ssh_get_error(session));
        return 1;
    }
    r = ssh_userauth_autopubkey(session, NULL);
    if(r != SSH_AUTH_SUCCESS){
        printf("Authentification failed: %s\n", ssh_get_error(session));
        return 1;
    }

    ssh_channel channel = ssh_channel_new(session);
    if(channel == NULL){
        ssh_disconnect(session);
        return 1;
    }

    r = ssh_channel_open_session(channel);
    if(r < 0){
        ssh_channel_close(channel);
        return 1;
    }

    ssh_channel_write(channel, "Hello!", 6);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);

    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}

