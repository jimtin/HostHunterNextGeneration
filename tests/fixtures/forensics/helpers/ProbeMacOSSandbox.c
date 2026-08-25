#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        return 64;
    }

    int network_socket = socket(AF_INET, SOCK_STREAM, 0);
    bool network_denied = network_socket < 0;
    if (network_socket >= 0) {
        struct sockaddr_in endpoint = {0};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(9);
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        network_denied = connect(
            network_socket,
            (const struct sockaddr *)&endpoint,
            sizeof(endpoint)) < 0 && errno == EPERM;
        close(network_socket);
    }

    int read_handle = open(argv[1], O_RDONLY);
    bool sensitive_read_denied = read_handle < 0 && errno == EPERM;
    if (read_handle >= 0) {
        close(read_handle);
    }

    int write_handle = open(argv[2], O_CREAT | O_EXCL | O_WRONLY, 0600);
    bool write_denied = write_handle < 0 && errno == EPERM;
    if (write_handle >= 0) {
        close(write_handle);
        unlink(argv[2]);
    }

    pid_t child = fork();
    bool fork_denied = child < 0 && errno == EPERM;
    if (child == 0) {
        _exit(0);
    }
    if (child > 0) {
        waitpid(child, NULL, 0);
    }

    printf(
        "{\"Event\":{\"NetworkDenied\":%s,"
        "\"SensitiveReadDenied\":%s,\"WriteDenied\":%s,"
        "\"ForkDenied\":%s}}\n",
        network_denied ? "true" : "false",
        sensitive_read_denied ? "true" : "false",
        write_denied ? "true" : "false",
        fork_denied ? "true" : "false");
    return 0;
}
