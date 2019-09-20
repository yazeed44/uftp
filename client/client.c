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
//TODO Add support for DNS argument
void check_arguments(int argc){
    if (argc != 3) {
        fprintf(stderr, "usage: ./client server_ip port\n");
        exit(1);
    }
}
struct addrinfo init_hints() {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
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
    memset(buf, 0, BUFFLEN);
    int len;
    while (recvfrom(sockfd, buf, BUFFLEN-1, 0,servinfo->ai_addr, &len) > 0){
        buf[BUFFLEN - 1] = '\0';
        printf("%s", buf);
        fflush(stdout);
        memset(buf, 0, BUFFLEN);
    }
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
    memset(buf, 0, strlen(buf));
    return send_to_server(sockfd, buf, strlen(buf), servinfo);
}

void send_file(int sockfd, FILE *src_file, struct addrinfo *servinfo){
    char filebuf[BUFFLEN];
    memset(filebuf, 0, BUFFLEN);
    int numbytes;
    int totalsent = 0;
    while ((numbytes = (fread(filebuf, 1, BUFFLEN,  src_file))) > 0){
        int sendbytes = send_to_server(sockfd, filebuf, numbytes, servinfo);
        memset(filebuf, 0, BUFFLEN);
        totalsent += sendbytes;
        }
    send_transmission_done_packet(sockfd, servinfo);
    printf("Sent a %i bytes\n", totalsent);
    
    fclose(src_file);
    
}
void handle_put_command(char cmd[], int sockfd, struct addrinfo *servinfo){
    char *filename = malloc(BUFFLEN);
    strcpy(filename, cmd);
    filename = strtok(filename, " ");
    filename = strtok(NULL, " ");
    FILE *file_destination =  fopen(filename, "rb");
    if(file_destination == NULL)
    {
        printf("ERROR - Failed to open file for sending\n");
    }   
    else {
        send_to_server(sockfd, cmd, strlen(cmd), servinfo); // Send the command and its arguments
        send_file(sockfd, file_destination, servinfo);
    }
}


int send_cmd(int sockfd, struct addrinfo *servinfo) {
    int numbytes;
    char cmd[BUFFLEN];
    memset(cmd, 0, BUFFLEN);
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