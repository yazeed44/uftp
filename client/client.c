#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define BUFFLEN 1024
//TODO add a check for when the file argument for put does not exist
void check_arguments(int argc){
    if (argc != 3) {
        fprintf(stderr, "usage: ./client server_ip port\n");
        exit(1);
    }
}
struct addrinfo init_hints() {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    return hints;
}

void init_servinfo( struct addrinfo **servinfo, char* argv[]) {
    struct addrinfo hints = init_hints();
    int rv;
    if (rv = (getaddrinfo(argv[1], argv[2], &hints, servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }
}

int create_socket(struct addrinfo *servinfo) {
    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sockfd == -1) {
            perror("talker: socket");
            exit(1);
    }
    return sockfd;
}

void print_response(int sockfd, struct addrinfo *servinfo){
    char buf[BUFFLEN];
    memset(buf,0,sizeof buf);
    int len;
    while (recvfrom(sockfd, buf, BUFFLEN-1, 0,servinfo->ai_addr, &len) > 0){
        buf[BUFFLEN - 1] = '\0';
        printf("%s", buf);
        fflush(stdout);
        memset(buf,0,sizeof buf);
    }
    /*int numbytes = recvfrom(sockfd, buf, BUFFLEN-1, 0,servinfo->ai_addr, &len);
    if (numbytes == -1){
        perror("print_response");
    }
    else {
        buf[BUFFLEN - 1] = '\0';
        printf("%s", buf);
        fflush(stdout);
        memset(buf,0,sizeof buf);
    }
    */
}

int send_to_server(int sockfd, char buf[], size_t buflen, struct addrinfo *servinfo){
    int numbytes;
    if ((numbytes = sendto(sockfd, buf, buflen, 0, servinfo->ai_addr, servinfo->ai_addrlen)) < 0){
        perror("talker: sendto");
    }
    return numbytes;
}

int send_transmission_done_packet(int sockfd, struct addrinfo *servinfo){
    char buf[BUFFLEN];
    memset(buf, 0,strlen(buf)); // Send a packet that tells the server that the file transmission is done
    return send_to_server(sockfd, buf, strlen(buf), servinfo);
}

size_t calculate_file_size(FILE *src_file){
    fseek(src_file, 0, SEEK_END);
    return ftell(src_file);
}
void send_file(int sockfd, FILE *src_file, struct addrinfo *servinfo){
    char filebuf[BUFFLEN];
    memset(filebuf, 0, BUFFLEN);
    size_t totalsize = calculate_file_size(src_file);
    // Convert fileSize integral # to string:
    char size_str[BUFFLEN];
    memset(size_str, 0, BUFFLEN);
    snprintf(size_str, BUFFLEN, "%d", (int) BUFFLEN);
 
    send_to_server(sockfd, size_str, sizeof(totalsize), servinfo); // Send the server the total size of the file
    fseek(src_file,0,SEEK_SET); // Reset the position of the file to first line
    while (totalsize > 0){
        memset(filebuf, 0, BUFFLEN);
        int readbytes = fread(filebuf, 1, sizeof(BUFFLEN) - 1, src_file);
        int sendbytes = send_to_server(sockfd, filebuf, strlen(filebuf), servinfo);
        totalsize -= sendbytes;
    }
    fclose(src_file);
    send_transmission_done_packet(sockfd, servinfo);
}
void handle_put_command(char cmd[], int sockfd, struct addrinfo *servinfo){
    char *filename = strtok(cmd, " ");
    filename = strtok(NULL, " ");
    FILE *file_destination =  fopen(filename, "rb");
    if(file_destination == NULL)
    {
        printf("ERROR - Failed to open file for sending\n");
        send_transmission_done_packet(sockfd, servinfo);
    }   
    else {
        send_file(sockfd, file_destination, servinfo);
    }
}


int send_cmd(int sockfd, struct addrinfo *servinfo) {
    int numbytes;
    char cmd[BUFFLEN];
    memset(cmd,0,sizeof cmd);
    fgets(cmd,BUFFLEN, stdin);
    cmd[strcspn(cmd, "\n")] = 0; // Remove the trailing newline from fgets input sock

    if (strcmp("exit", cmd) == 0){
        send_to_server(sockfd, cmd, strlen(cmd), servinfo);
        freeaddrinfo(servinfo);
        close(sockfd);
        exit(0);
    }
    else if (strcmp("ls", cmd) == 0){
        send_to_server(sockfd, cmd,strlen(cmd), servinfo);
        print_response(sockfd, servinfo);
    }

    else if (strstr(cmd, "put") != NULL) {
        send_to_server(sockfd, cmd, strlen(cmd), servinfo);
        handle_put_command(cmd, sockfd, servinfo);
    }

    else {
        // Unknown command
        send_to_server(sockfd, cmd, strlen(cmd), servinfo);
        print_response(sockfd, servinfo);
    }
    return numbytes;
}


void handle_communications(int sockfd, struct addrinfo *servinfo){
    int numbytes;
    while (1) {
        numbytes = send_cmd(sockfd, servinfo);
    }
}
int main(int argc, char* argv[]) {
    struct addrinfo *servinfo;
    check_arguments(argc);
    init_servinfo(&servinfo, argv);
    int sockfd = create_socket(servinfo);
    handle_communications(sockfd, servinfo);
    freeaddrinfo(servinfo);
    close(sockfd);
    return 0;
}