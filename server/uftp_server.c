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
#define BUFFLEN 14000 //Temporary
#define TIMEOUT_SEC 1
struct addrinfo init_hints() {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    return hints;
}

char* init_port(int argc, char* argv[]){
    if (argc != 2) {
        fprintf(stderr, "usage: ./server port\n");
        exit(1);
    }
    else {
        return argv[1];
    }
}

void init_servinfo( struct addrinfo **servinfo, char *port) {
    struct addrinfo hints = init_hints();
    int rv;
    if (rv = (getaddrinfo(NULL, port, &hints, servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }
}

int create_socket(struct addrinfo *p){
    int sockfd = socket(p -> ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1)
        perror("create_socket: socket");
    return sockfd;
}

int bind_to_socket(int sockfd, struct addrinfo *p) {
    int bind_res = bind(sockfd, p->ai_addr, p->ai_addrlen);
    if (bind_res){
        close(sockfd);
        perror("bind_to_socket: bind");
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
        fprintf(stderr, "socket_bind: failed to bind socket");
        exit(1);
    }
    return new_sockfd;
}

unsigned char checksum_of_file(FILE *src_file){
    //Assumes that the file is open already
    unsigned char checksum = 0;
    fseek(src_file, 0, SEEK_SET); //Set the file's cursor to start
    while (!feof(src_file) && !ferror(src_file)) {
        checksum ^= fgetc(src_file);
    }
    return checksum;
}


int receive_msg(int sockfd, char buf[], size_t buflen,struct sockaddr_storage *client_addr){
    socklen_t addr_len = sizeof *client_addr;
    memset(buf, 0, buflen);
    int numbytes = recvfrom(sockfd, buf, buflen, 0,(struct sockaddr *)client_addr, &addr_len);
    buf[numbytes] = '\0';
    return numbytes;
}

int send_to_client(int sockfd, char *buf, size_t buflen,struct sockaddr_storage client_addr) {
    socklen_t addr_len = sizeof client_addr;
    int numbytes = sendto(sockfd, buf, buflen, 0, (struct sockaddr *)&client_addr, addr_len);
    if(numbytes == -1){
        perror("send_to_client: sendto");
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
        perror("handle_ls_cmd: popen");
        exit(1);
    }
 
    int total_size = 0;
    while (fgets(output, sizeof output - 1,  fp) != NULL){
        send_to_client(sockfd, output, strlen(output),client_addr);
    }
    send_transmission_done_packet(sockfd, client_addr);
    pclose(fp);
}

void send_checksum_packet(int sockfd, FILE*src_file, struct sockaddr_storage *client_addr){
    unsigned char checksum = checksum_of_file(src_file);
    char checksumPacket[sizeof(checksum) * 8 + 1];
    memset(checksumPacket, 0, sizeof(checksum) * 8 + 1);
    sprintf(checksumPacket, "%c", checksum);
    send_to_client(sockfd, checksumPacket, strlen(checksumPacket), *client_addr);
}

void set_timeout(int sockfd, int seconds){
    struct timeval tv;
    tv.tv_sec = seconds; 
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) 
        perror("set_timeout: setsockopt");
}
int assure_arrival_of_packet(int sockfd, unsigned int numPacket,char filebuf[], size_t buflen,struct sockaddr_storage *client_addr){
    int sentbytes = 0;
    char ackBuf[BUFFLEN];
    while (1) {
        int curBytes = send_to_client(sockfd, filebuf, buflen, *client_addr); // Send the file chunk packet
        sentbytes += curBytes;
        //Wait for acknowledgment
        set_timeout(sockfd, TIMEOUT_SEC); // Enable timeout
        int ackbytes = receive_msg(sockfd, ackBuf, BUFFLEN, client_addr); // Will timeout after 1 sec
        
        if (ackbytes > 0){
            //If it didn't time out
             if (atoi(ackBuf) == numPacket){
                set_timeout(sockfd, 0); // Disable timeout
                break; // We succesfully received the acknowledgement for the packet
            }
        }
    }
    return sentbytes;
}

void send_file(int sockfd, FILE *src_file, struct sockaddr_storage client_addr){
    char filebuf[BUFFLEN];
    
    memset(filebuf, 0, BUFFLEN);
    int readbytes;
    int totalsent = 0;
    unsigned int curPacket = 0; // AKA sequence number
    while ((readbytes = (fread(filebuf, 1, BUFFLEN,  src_file))) > 0){
        int sentbytes = assure_arrival_of_packet(sockfd, curPacket, filebuf, readbytes, &client_addr); // Won't exit until the packet has been assured to have arrived at server
        memset(filebuf, 0, BUFFLEN);
        totalsent += sentbytes;
        curPacket++;
        }
    send_transmission_done_packet(sockfd, client_addr);
    send_checksum_packet(sockfd, src_file, &client_addr);
    //send_transmission_done_packet(sockfd, client_addr);
    fclose(src_file);
}

int check_file_exists(const char * filename){
    /* try to open file to read */
    FILE *file;
    if (file = fopen(filename, "r")){
        fclose(file);
        return 1;
    }
    return 0;
}
void handle_get_cmd(char buf[], int sockfd, struct sockaddr_storage client_addr) {
    char *filename = strtok(buf, " ");
    filename = strtok(NULL, " ");
    FILE* fp = fopen(filename, "r");
    if (fp == NULL || !check_file_exists(filename)){
        char msg[] = "File open failed!\n";
        send_to_client(sockfd, msg, strlen(msg), client_addr);
        send_transmission_done_packet(sockfd, client_addr);
    }

    else {
        send_file(sockfd, fp, client_addr);
    }
}

int acknowledge_packet(int sockfd,unsigned int curPacket,struct sockaddr_storage client_addr){
    char curpacketStr[sizeof(curPacket) * 8+ 1];
    sprintf(curpacketStr, "%u", curPacket);
    return send_to_client(sockfd, curpacketStr, strlen(curpacketStr), client_addr);
}

void receive_file(int sockfd, FILE *dst_file , struct sockaddr_storage *client_addr){
    char filebuf[BUFFLEN]; 
    int recvBytes = 0;
    int ackBytes = 0;
    int totalReceived = 0;
    unsigned int curPacket = 0; // AKA sequence number
    char lastbuf[BUFFLEN];
    memset(filebuf, 0, BUFFLEN);
    memcpy(lastbuf, filebuf, BUFFLEN);
    while ((recvBytes = receive_msg(sockfd, filebuf, BUFFLEN, client_addr)) > 0){
        ackBytes += acknowledge_packet(sockfd, curPacket, *client_addr);
        if (lastbuf == filebuf) {
            //This case happens when we send an ack but the client doesn't receive the ack so the client will resend the msg again

            continue;
        }

        else {
            fwrite(filebuf, recvBytes, 1, dst_file);
            memcpy(lastbuf, filebuf, BUFFLEN);
            totalReceived += recvBytes;
            curPacket++;
        }
        //Will exit when recives a packet with buffer length = 0, which is our transmission done packet (send_transmission_done_packet)
    }
    fclose(dst_file);
}



void verify_file(int sockfd, char *filename, struct sockaddr_storage *client_addr){
    FILE *src_file = fopen(filename, "rb");
    unsigned char checksum = checksum_of_file(src_file);
    fclose(src_file);

    char checksumPacket[sizeof(checksum) * 8 + 1];
    memset(checksumPacket, 0, sizeof(checksum) * 8 + 1);
    sprintf(checksumPacket, "%c", checksum);

    char checksumbuf[BUFFLEN];
    int recvbytes = receive_msg(sockfd, checksumbuf, BUFFLEN, client_addr); // Will timeout after 1 second
    char *msg;
    if (recvbytes > 0){
        if (strcmp(checksumbuf, checksumPacket) == 0)
            msg = "Checksum of the client's file and received file has been compared, and they are equal!\n";
        else 
            msg = "Checksum of the client's file and received file has been compared, and they are not equal! Please delete and resend the file.\n";
    }

    else 
        msg = "Checksum from the client didn't arrive, and thus the program can't make any conclusions on whether the file has been received correctly\n";
    
    send_to_client(sockfd, msg, strlen(msg), *client_addr);
    send_transmission_done_packet(sockfd, *client_addr);
}
void handle_put_cmd(char buf[], int sockfd, struct sockaddr_storage *client_addr){ 
    char *filename = strtok(buf, " ");
    filename = strtok(NULL, " ");
    FILE *file_destination =  fopen(filename, "wb");
    if(file_destination == NULL) {
        perror("ERROR - Failed to open file for writing\n");
        char *msg = "Failed to open the file\n";
        send_to_client(sockfd, msg, strlen(msg), *client_addr);
        send_transmission_done_packet(sockfd, *client_addr);
    }
        
    else
    {
        receive_file(sockfd, file_destination, client_addr);
        verify_file(sockfd, filename, client_addr);
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
    socklen_t addr_len = sizeof client_addr;
    while (1) {
        numbytes = receive_msg(sockfd, buf, sizeof(buf),&client_addr);
        handle_commands(buf, sockfd, client_addr);   
    }
}
int main(int argc, char* argv[]) {
    char *port = init_port(argc, argv);
    struct addrinfo *servinfo;
    init_servinfo(&servinfo, port);
    int sockfd = socket_bind(servinfo);
    freeaddrinfo(servinfo);
    handle_communication(sockfd);
    return 0;
}