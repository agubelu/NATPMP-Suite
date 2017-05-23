#ifndef PERFORMANCE_CLIENT_NETWORK_H_
#define PERFORMANCE_CLIENT_NETWORK_H_

#define NATPMP_PORT 5351
#define NETWORK_BUFFER_LEN 65536

int send_and_receive(int socket, void* buffer, size_t buffer_size, struct sockaddr* dest_addr, int dest_addt_size, int* data, int data_size);

#endif //PERFORMANCE_CLIENT_NETWORK_H
