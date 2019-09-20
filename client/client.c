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
#define BUFFLEN 14000 //TODO look for optimal buffer length
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



int send_to_server(int sockfd, char buf[], size_t buflen, struct addrinfo *servinfo){
    int numbytes;
    if ((numbytes = sendto(sockfd, buf, buflen, 0, servinfo->ai_addr, servinfo->ai_addrlen)) < 0){
        
        perror("talker: sendto");
    }
    return numbytes;
}

int receive_msg(int sockfd, char buf[], size_t buflen,struct addrinfo *servinfo){
    memset(buf, 0, buflen);
    int len;
    int numbytes = recvfrom(sockfd, buf, buflen, 0,servinfo -> ai_addr, &len);
    if(numbytes == -1){
        perror("recvfrom");
        exit(1);
    }
    buf[numbytes] = '\0';
    return numbytes;
}

void print_response(int sockfd, struct addrinfo *servinfo){
    char buf[BUFFLEN];
    int len;
    while (receive_msg(sockfd, buf, BUFFLEN-1,servinfo) > 0){
        buf[BUFFLEN - 1] = '\0';
        printf("%s", buf);
        fflush(stdout);
    }
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

char* get_filename(char cmd[]){
    //Extract file name from command
    char *filename = malloc(BUFFLEN);
    strcpy(filename, cmd);
    filename = strtok(filename, " ");
    filename = strtok(NULL, " ");
    return filename;
}

void handle_put_command(char cmd[], int sockfd, struct addrinfo *servinfo){
    char *filename = get_filename(cmd);
    FILE *file_destination =  fopen(filename, "rb");
    if(file_destination == NULL)
    {
        printf("ERROR - Failed to open file for sending\n");
    }   
    else {
        send_to_server(sockfd, cmd, strlen(cmd), servinfo); // Send the command and its arguments
        send_file(sockfd, file_destination, servinfo);
        print_response(sockfd, servinfo);
    }
}

void receive_file(int sockfd, FILE *dst_file , struct addrinfo *servinfo){
    char filebuf[BUFFLEN]; 
    int numbytes;
    int totalReceived = 0;
    while ((numbytes = receive_msg(sockfd, filebuf, BUFFLEN, servinfo)) > 0){
        fwrite(filebuf, numbytes, 1, dst_file);
        totalReceived += numbytes;
        //Will exit when recives a packet with buffer length = 0, which is our transmission done packet (send_transmission_done_packet)
    }
    printf("Total received %i bytes\n", totalReceived); // TODO delete this
    fclose(dst_file);
}

void handle_get_command(char cmd[], int sockfd, struct addrinfo *servinfo){
    char *filename = get_filename(cmd);
    FILE *file_destination =  fopen(filename, "wb");
    if(file_destination == NULL)
    {
        printf("ERROR - Failed to open file for writing\n");
    }

    else {
        send_to_server(sockfd, cmd, strlen(cmd), servinfo);
        receive_file(sockfd, file_destination, servinfo);
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

    else if (strstr(cmd, "get") != NULL)
        handle_get_command(cmd, sockfd, servinfo);

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