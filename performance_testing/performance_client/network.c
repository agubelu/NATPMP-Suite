#include <sys/socket.h>

int send_and_receive(int socket, void* buffer, size_t buffer_size, struct sockaddr* dest_addr, int dest_addt_size, void* data, int data_size) {
    int res_send = sendto(socket, data, data_size, 0, (struct sockaddr*) dest_addr, dest_addt_size);
    if(res_send == -1) {
        return res_send;
    }

    return recvfrom(socket, buffer, buffer_size, 0, (struct sockaddr*) dest_addr, &dest_addt_size);
}