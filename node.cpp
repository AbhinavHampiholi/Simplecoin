/**
 * This is a node in a p2p network
 * 
 * This means that it is basically both a server and a client
 * 
 * */
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h>
#include <bits/stdc++.h>
#include <thread>

#define SA struct sockaddr 
#define  MAX 1000
using namespace std;

int PORT =  9005; //or whatever. Will be rewritten by command line args

void listener_func(int sockfd){
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);
    char buffComm[MAX];
    while(1){
        bzero(buffComm, MAX); 
        int connfd = accept(sockfd, (SA*)&cli, &len); 
        if (connfd < 0) { 
            printf("Server accept failed...\n"); 
            exit(0); 
        }  
		read(connfd, buffComm, sizeof(buffComm));
        // getsockname(sockfd, (SA*)&cli, &len); 
        printf("[%d] : %s",(int) cli.sin_port, buffComm);
        // break;
    }

}

void sendTo(string ip, int port, char *data){
    char ip_char[MAX];
    char data_char[MAX];
    strcpy(ip_char, ip.c_str());
    strcpy(data_char, data);
    // printf("Sending %s to %d\n", data_char, port);
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("Socket creation failed...\n"); 
		exit(0); 
	} 

	// assign IP, PORT 
    struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr)); 

	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = inet_addr(ip_char); 
	servaddr.sin_port = htons(port); 

    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
		printf("Connection with the server failed...\n"); 
		exit(0); 
	} 
	
    write(sockfd, data_char, sizeof(data_char)); //writing command to server
    close(sockfd);
}

int main(int argc, char **argv) {
    //----------UNCOMMENT THIS LATER

    if (argc!=2){
		printf("Usage: [executable] [list_PORT]");
		return 0;
	}
    PORT = atoi(argv[1]);
    //-------------------
    
    //-------------DEBUG CODE
    // PORT = atoi(argv[1]);
    // string IP = "127.0.0.1";
    //---------------------


    cout<<"LISTENING@"<<PORT<<endl;

    int sockfd, connfd;
    socklen_t len; 
	struct sockaddr_in servaddr, cli; 

	//Create and verify socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("Socket creation failed...\n"); 
		exit(0); 
	} 
	else printf("Socket successfully created...\n"); 

	bzero(&servaddr, sizeof(servaddr)); 

    servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT); 

	// Binding newly created socket to the given IP
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
		printf("Socket bind failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully binded...\n"); 

	// Now server is ready to listen
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		exit(0); 
	} 
	else
		printf("Node listening...\n"); 
    cout<<"[IP] [PORT] [your message]\n";
    
    thread listener (listener_func, sockfd);
    while(1){
        cout<<"> ";
        string ip = "127.0.0.1";
        char data[MAX];
        int port;
        cin>>ip;
        cin>>port;
        fgets(data, 900, stdin);
        // cin>>ip>>port>>data;
        if(port==0){
            close(sockfd);
            exit(0);
        }
        sendTo(ip, port, data);
    }
    close(sockfd); 
    return 0;
}