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
#define BUFFLEN 14000 
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

void set_timeout(int sockfd, long tv_sec, long tv_usec){
    struct timeval tv;
    tv.tv_sec = tv_sec; 
    tv.tv_usec = tv_usec;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) 
        perror("set_timeout: setsockopt");
}
int create_socket(struct addrinfo *servinfo) {
    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sockfd == -1) {
            perror("create_socket: socket");
            exit(1);
    }
    set_timeout(sockfd, 1, 0);

    return sockfd;
}

int send_to_server(int sockfd, char buf[], size_t buflen, struct addrinfo *servinfo){
    int numbytes;
    if ((numbytes = sendto(sockfd, buf, buflen, 0, servinfo->ai_addr, servinfo->ai_addrlen)) < 0){
        perror("send_to_server: sendto");
    }
    return numbytes;
}

int receive_msg(int sockfd, char buf[], size_t buflen,struct addrinfo *servinfo){
    memset(buf, 0, buflen);
    int len = sizeof(servinfo);
    int numbytes = recvfrom(sockfd, buf, buflen, 0,servinfo -> ai_addr, &len);
    buf[numbytes] = '\0';
    return numbytes;
}

void print_response(int sockfd, struct addrinfo *servinfo){
    //This function will output whatever it receives from the server on the screen until an empty packet has been received (send_transmission_done_packet)
    char buf[BUFFLEN];
    set_timeout(sockfd, 2,0); // Set a considerably long time in case the termination packet will not arrive
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

unsigned char checksum_of_file(FILE *src_file){
    //Assumes that the file is open already
    fseek(src_file, 0, SEEK_SET); // Set the file cursor to start
    unsigned char checksum = 0;
    while (!feof(src_file) && !ferror(src_file)) {
        checksum ^= fgetc(src_file);
    }
    return checksum;
}

void send_checksum_packet(int sockfd, FILE*src_file, struct addrinfo *servinfo){
    unsigned char checksum = checksum_of_file(src_file);
    printf("Raw checksum: %#x\n", checksum); // TEMP
    char checksumPacket[sizeof(checksum) * 8 + 1];
    memset(checksumPacket, 0, sizeof(checksum) * 8 + 1);
    sprintf(checksumPacket, "%c", checksum);
    send_to_server(sockfd, checksumPacket, strlen(checksumPacket), servinfo); 
    printf("Sent checksum packet\n"); // TEMP
}
int assure_arrival_of_packet(int sockfd, unsigned int numPacket,char filebuf[], size_t buflen,struct addrinfo *servinfo){
    int sentbytes = 0;
    char ackBuf[BUFFLEN];
    while (1) {
        int curBytes = send_to_server(sockfd, filebuf, buflen, servinfo); // Send the file chunk packet
        sentbytes += curBytes;
        printf("assure_arrival_of_packet: Sent %u bytes. Waiting for ack now\n", curBytes);
        //Wait for acknowledgment
        set_timeout(sockfd, 1,0);
        int ackbytes = receive_msg(sockfd, ackBuf, BUFFLEN, servinfo); // Will timeout after 1 sec
        
        if (ackbytes > 0){
            //If it didn't time out
            printf("Raw ackbuf: %s\n", ackBuf);
            printf("assure_arrival_of_packet: Received ack. Will verify it now. %u ?= %u\n", atoi(ackBuf), numPacket);
             if (atoi(ackBuf) == numPacket){
                printf("assure_arrival_of_packet: Packet %u has been verified\n", atoi(ackBuf));
                set_timeout(sockfd, 0, 0);
                break; // We succesfully received the acknowledgement for the packet
            }
            else {
                printf("assure_arrival_of_packet: Ack is not approved. %s\n", ackBuf);
                exit(1); //TEMP
            }
        }
           
    }
    return sentbytes;
}

void send_file(int sockfd, FILE *src_file, struct addrinfo *servinfo){
    char filebuf[BUFFLEN];
    
    memset(filebuf, 0, BUFFLEN);
    int readbytes;
    int totalsent = 0;
    unsigned int curPacket = 0; // AKA sequence number
    while ((readbytes = (fread(filebuf, 1, BUFFLEN,  src_file))) > 0){
        int sentbytes = assure_arrival_of_packet(sockfd, curPacket, filebuf, readbytes, servinfo); // Won't exit until the packet has been assured to have arrived at server
        printf("send_file: Sent packet %u\n", curPacket); // TEMP
        memset(filebuf, 0, BUFFLEN);
        totalsent += sentbytes;
        curPacket++;
        }
    printf("Sent a %u bytes\n", totalsent); // TEMP
    send_transmission_done_packet(sockfd, servinfo);
    send_checksum_packet(sockfd, src_file, servinfo);
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
        send_to_server(sockfd, cmd, strlen(cmd), servinfo); // Send the command and its arguments so the server can expect the file
        send_file(sockfd, file_destination, servinfo);
        print_response(sockfd, servinfo);
    }
}
void verify_file(int sockfd, char *filename, struct addrinfo *servinfo){
    FILE *src_file = fopen(filename, "rb");
    if (src_file == NULL)
        return;
    
    unsigned char checksum = checksum_of_file(src_file);
    printf("Raw checksum: %#x\n", checksum);
    fclose(src_file);

    char checksumPacket[sizeof(checksum) * 8 + 1];
    sprintf(checksumPacket, "%c", checksum);

    char checksumbuf[BUFFLEN];
    int recvbytes = receive_msg(sockfd, checksumbuf, BUFFLEN, servinfo);
    if (recvbytes > 0){
        if (strcmp(checksumbuf, checksumPacket) == 0)
            printf("Checksum of the server's file and received file has been compared, and they are equal!\n");
        
        else 
            printf("Checksum of the server's file and received file has been compared, and they are not equal! Please delete and redownload the file.\n");
        
    }
    else 
        //If the checksum packet hasn't arrived
        printf("Checksum from server didn't arrive, and thus the program can't make any conclusions on whether the file has been received correctly\n");
    
}

int acknowledge_packet(int sockfd,unsigned int curPacket,struct addrinfo *servinfo){
    char curpacketStr[sizeof(curPacket) * 8+ 1];
    sprintf(curpacketStr, "%u", curPacket);
    printf("acknowledge_packet: Sending ack for packet %u\n", atoi(curpacketStr));
    return send_to_server(sockfd, curpacketStr, strlen(curpacketStr), servinfo);
}


void receive_file(int sockfd, FILE *dst_file , struct addrinfo *servinfo){
    char filebuf[BUFFLEN]; 
    int recvBytes = 0;
    int ackBytes = 0;
    int totalReceived = 0;
    unsigned int curPacket = 0; // AKA sequence number
    char lastbuf[BUFFLEN];
    while ((recvBytes = receive_msg(sockfd, filebuf, BUFFLEN, servinfo)) > 0){
        ackBytes += acknowledge_packet(sockfd, curPacket, servinfo);
        if (lastbuf == filebuf) {
            //This case happens when we send an ack but the client doesn't receive the ack so the client will resend the msg again
            printf("The client resent packet #%d. Skipping\n", curPacket);

            continue;
        }

        else {
            printf("receive_file: Received %u packet. Will proceed to write to the file\n", curPacket);
            fwrite(filebuf, recvBytes, 1, dst_file);
            memcpy(lastbuf, filebuf, BUFFLEN);
            totalReceived += recvBytes;
            curPacket++;
        }
        //Will exit when recives a packet with buffer length = 0, which is our transmission done packet (send_transmission_done_packet)
    }
    printf("Total received %u bytes\n", totalReceived); // TODO delete this
    fclose(dst_file);
}

void delete_if_file_does_not_exist(int sockfd, char *filename, struct addrinfo *servinfo){
    //The server will not send a message to the client.c that the file does not exist
    //Instead it writes it to filename buffer
    //In this function we will check if the file buffer matches those of who do not exist on the server
    FILE *src_file = fopen(filename, "r");
    char filebuf[BUFFLEN];
    fread(filebuf, BUFFLEN, 1, src_file);
    fclose(src_file);
    if (strcmp("File open failed!\n", filebuf) == 0){
        printf("%s does not exist on server\n", filename);
        remove(filename);
    }
    
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
        delete_if_file_does_not_exist(sockfd, filename, servinfo);
        verify_file(sockfd, filename, servinfo);
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
