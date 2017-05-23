#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "network.h"

void die(char* str) {
    printf("%s\n", str);
    fflush(stdout);
    exit(1);
}

int main(int argc, char* argv[]) {
    //Parse the command-line arguments
    int protocol_version = 0;
    int iterations = 1000;
    bool use_tls = false;
    char* tls_cert = NULL;
    char* tls_key = NULL;
    char* gateway = NULL;

    int opt;

    while((opt = getopt(argc, argv, "1tc:k:g:n:")) != -1) {
        switch(opt) {
            case '1':
                protocol_version = 1; break;
            case 't':
                use_tls = true; break;
            case 'c':
                tls_cert = optarg; break;
            case 'k':
                tls_key = optarg; break;
            case 'g':
                gateway = optarg; break;
            case 'n':
                iterations = optarg; break;
        }
    }

    // Check that the gateway is set
    if(!gateway) {
        die("Please, provide a gateway address using the -g flag.");
    }

    // Check that if we're using TLS both the cert and key exist
    if(use_tls && (!tls_cert || !tls_key)) {
        die("Must specify a client certificate and key when using secure requests via -c and -k.");
    }

    // Create the UDP socket that will be used
    int sock_client = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_client == -1) {
        die(strcat("Error creating the client socket: ", strerror(errno)));
    }

    // Bind the UDP socket to the corresponding address
    // creating the corresponding struct
    struct sockaddr_in client_addr;
    int addr_size = sizeof(client_addr);

    memset((char*) &client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(0);

    if(bind(sock_client, (struct sockaddr*) &client_addr, sizeof(client_addr)) == -1) {
        die(strcat("Error while binding socket: ", strerror(errno)));
    }

    // Set a timeout of 0.5 seconds for the socket when receiving data
    struct timeval tval;
    tval.tv_sec = 0;
    tval.tv_usec = 500000;
    setsockopt(sock_client, SOL_SOCKET, SO_RCVTIMEO, &tval, sizeof(tval));

    // Initialize the response buffer and the struct for the destination
    char response_buffer[NETWORK_BUFFER_LEN];
    struct sockaddr_in router_addr;
    memset((char*) &router_addr, 0, sizeof(router_addr));
    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(NATPMP_PORT);

    if(inet_aton(gateway, &router_addr.sin_addr) == 0) {
        die(strcat("inet_aton failed: ", strerror(errno)));
    }

    // Start time for performance measurement
    clock_t start_time = clock();
    // Counter for return codes
    int results[9] = { 0 };
    // Init the cert and key if needed
    char* cert_bytes = NULL;
    char* key_bytes = NULL;
    //TODO
    /*if(use_tls) {

    }*/

    // Begin iterations
    for(int i = 0; i < iterations; i++) {
        // Clear the buffer
        memset(response_buffer, '\0', NETWORK_BUFFER_LEN);
    }

    clock_t end_time = clock();

    //TODO int c = send_and_receive(sock_client, response_buffer, NETWORK_BUFFER_LEN, &router_addr, addr_size, msg, strlen(msg));

    return 0;

}