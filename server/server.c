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
#define PORT "5454"
#define BUFFLEN 1024 //Temporary
#define STANDBY_MODE 0
#define PUT_MODE 1
#define GET_MODE 2

int mode = STANDBY_MODE; // When the server is sending or reciving files, It will stop reciving other commands. 
// This variable will be used to check which mode is the server on

struct addrinfo init_hints() {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    return hints;
}

void init_servinfo( struct addrinfo **servinfo) {
    struct addrinfo hints = init_hints();
    int rv;
    if (rv = (getaddrinfo(NULL, PORT, &hints, servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }
}

int create_socket(struct addrinfo *p){
    int sockfd = socket(p -> ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1)
        perror("listener: socket");
    return sockfd;
}

int bind_to_socket(int sockfd, struct addrinfo *p) {
    int bind_res = bind(sockfd, p->ai_addr, p->ai_addrlen);
    if (bind_res){
        close(sockfd);
        perror("listener: bind");
    }
    return bind_res;
}
int socket_bind(struct addrinfo *servinfo) {
    struct addrinfo *p;
    int new_sockfd;
    for (p = servinfo; p != NULL; p = p-> ai_next) {
        new_sockfd = create_socket(p);
        int bind = bind_to_socket(new_sockfd, p);
        if (new_sockfd == -1 || bind == -1)
            continue;
        else
            break;
    }
    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        exit(1);
    }
    return new_sockfd;
}


int receive_msg(int sockfd, char buf[], size_t buflen,struct sockaddr_storage *client_addr){
    socklen_t addr_len = sizeof *client_addr;
    memset(buf, 0, buflen);
    int numbytes = recvfrom(sockfd, buf, buflen, 0,(struct sockaddr *)client_addr, &addr_len);
    if(numbytes == -1){
        perror("recvfrom");
        exit(1);
    }
    buf[numbytes] = '\0';
    return numbytes;
}

int send_to_client(int sockfd, char *buf, size_t buflen,struct sockaddr_storage client_addr) {
    socklen_t addr_len = sizeof client_addr;
    int numbytes = sendto(sockfd, buf, buflen, 0, (struct sockaddr *)&client_addr, addr_len);
    if(numbytes == -1){
        perror("sendto");
        exit(1);
    }
    return numbytes;
    
}

void send_transmission_done_packet(int sockfd, struct sockaddr_storage clientaddr){
    char buf[BUFFLEN];
    memset(buf, 0,strlen(buf)); // Send a packet that tells the server that the file transmission is done
    send_to_client(sockfd, buf, strlen(buf), clientaddr);
}
void handle_ls_cmd(int sockfd, struct sockaddr_storage client_addr){
    FILE *fp = popen("/bin/ls", "r");
    char output[BUFFLEN];

    if (fp == NULL)
    {
        perror("popen() failed.");
        exit(1);
    }
 
    int total_size = 0;
    while (fgets(output, sizeof output - 1,  fp) != NULL){
        send_to_client(sockfd, output, strlen(output),client_addr);
    }
    send_transmission_done_packet(sockfd, client_addr);
    pclose(fp);
}

void handle_get_cmd(char buf[], int sockfd, struct sockaddr_storage client_addr) {
    char *filename = strtok(buf, " ");
    filename = strtok(NULL, " ");
    FILE* fp = fopen(filename, "r");
    if (fp == NULL){
        char msg[] = "File open failed!\n";
        send_to_client(sockfd, msg, strlen(msg), client_addr);
    }

    else {
        //The file exists
        //TODO
        send_transmission_done_packet(sockfd, client_addr);
        fclose(fp);
    }
}

void handle_put_cmd(char buf[], int sockfd, struct sockaddr_storage *client_addr){ 
    char *filename = strtok(buf, " ");
    filename = strtok(NULL, " ");
    FILE *file_destination =  fopen(filename, "wb");
    if(file_destination == NULL)
    {
        printf("ERROR - Failed to open file for writing\n");
    }

    else {
        memset(buf, 0, BUFFLEN);
        receive_msg(sockfd, buf, BUFFLEN - 1, client_addr);
        int totalbytes = atoi(buf); // The total number of bytes for this file
        while (totalbytes > 0) {
            memset(buf, 0, BUFFLEN);
            int numbytes = receive_msg(sockfd, buf, BUFFLEN - 1, client_addr);
            int writebytes = fwrite(buf, strlen(buf), 1, file_destination);
            if (writebytes != numbytes){
                //fprintf(stderr, "%s\n", explain_fwrite(buf, strlen(buf), 1, file_destination));
                //TODO handle exception
            }
            totalbytes -= numbytes;
        }
        printf("Got out of recvfrom\n");
        //printf("Sent %i packets \n", count);
        fclose(file_destination);
    }
}

void handle_delete_cmd(char buf[], int sockfd, struct sockaddr_storage client_addr){
    char *filename = strtok(buf, " ");
    filename = strtok(NULL, " ");

    int result = remove(filename);
    if (result == 0){
        char msg[] = "File has been deleted successfully\n";
        send_to_client(sockfd, msg, strlen(msg), client_addr);
        send_transmission_done_packet(sockfd, client_addr);
    }
    else {
        //Failed to delete the file
        char msg[] = "Error while deleting the file\n";
        send_to_client(sockfd, msg, strlen(msg), client_addr);
        send_transmission_done_packet(sockfd, client_addr);
    }
}
void handle_commands(char buf[], int sockfd, struct sockaddr_storage client_addr) { 
    buf[strcspn(buf, "\n")] = 0; // Remove the trailing newline from input
    if (strcmp(buf,"ls") == 0)
        handle_ls_cmd(sockfd, client_addr); 
    else if (strstr(buf, "get") != NULL) 
        handle_get_cmd(buf, sockfd, client_addr);
    else if (strstr(buf,"put") != NULL)
        handle_put_cmd(buf,sockfd,&client_addr);
    else if (strstr(buf, "delete") != NULL)
        handle_delete_cmd(buf, sockfd, client_addr);
    else if (strcmp(buf,"exit") == 0){
        send_transmission_done_packet(sockfd, client_addr);
        close(sockfd);
        exit(0);
    }

    else {
        //The command was not understood
        strcat(buf, ": This command was not understood\n");
        send_to_client(sockfd, buf, strlen(buf),client_addr);
        send_transmission_done_packet(sockfd, client_addr);
    }
}
void handle_communication(int sockfd) {
    int numbytes;
    struct sockaddr_storage client_addr;
    char buf[BUFFLEN];
    memset(buf, 0, BUFFLEN);
    socklen_t addr_len = sizeof client_addr;

    while (1) {
        numbytes = receive_msg(sockfd, buf, sizeof(buf),&client_addr);
        handle_commands(buf, sockfd, client_addr);   
    }
}
int main(void) {
    struct addrinfo *servinfo;
    init_servinfo(&servinfo);
    int sockfd = socket_bind(servinfo);
    freeaddrinfo(servinfo);
    handle_communication(sockfd);
    return 0;
}