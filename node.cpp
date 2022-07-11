/**
 * This is a node in a p2p network
 * 
 * This means that it is basically both a server and a client
 * 
 * 
 * Let ADD be the address of the node i.e [IP PORT PUBKEY]
 * 
 * Commands to send data
 * INIT_PEERS ip port : sends a message of the form [add INIT_PEERS] to (ip, port)
 * INIT_BLOCKS ip port : sends a message of the form [add INIT_BLOCKS] to (ip, port)
 * BCAST_ID : sends a message to all known_peers of the form [add INTRO]
 * BCAST_TX tx : sends a message to all known_peers of the form [add TX tx]
 * BCAST_BLK blk : sends a message to all known_peers of the form [add BLK blk]
 * CHAT ip port msg : sends a message of the form [add CHAT msg] to (ip, port) 
 * 
 * Expected responses on receiving
 * req_add INIT_PEERS : send a message to req_add of the form [add INIT_PEERS_REPLY peers] where peers are all known_peers
 * req_add INIT_BLOCKS : send a message to req_add of the form [add INIT_BLOCKS_REPLY blocks] where blocks are all known_blocks
 * req_add INTRO : add req_add to known_peers
 * req_add TX tx : add tx to pending_tx
 * req_add BLK blk : verify if blk is valid. If valid, append to known_blocks and  remove transaction from 
 * req_add CHAT  msg : print the chat on stdout
 * req_add INIT_PEERS_REPLY peers : add peers to known_peers
 * req_add INIT_BLOCKS_REPLY blocks : set known_blocks := blocks
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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include "node.hpp"
#include "json.hpp"


#define SA struct sockaddr 
#define  MAX 1000
using namespace std;
using json = nlohmann::json;

vector <blockchain::node> known_peers;

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
        printf("[%d] : %s> ",(int) cli.sin_port, buffComm);
        // break;
    }

}

void sendTo(string ip, int port, char *data){
    char ip_char[MAX];
    char data_char[MAX];
    strcpy(ip_char, ip.c_str());
    strcpy(data_char, data);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
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

int init_listen_port(int port){
    int sockfd;
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
	servaddr.sin_port = htons(port); 

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
    
    return sockfd; 
}

//------SHA256 FUNCTIONS------

string sha256(const string str){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void sha256_digest(const string str, unsigned char * hash){
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
}

//------------------------


//------DIGITAL SIGNATURE FUNCTIONS-----

/**
 * prv_key should be a random hex string of length 64.
 * This represents a random number from 0 to 2^256-1
 * For example 6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C
 * It must be kept secret!
 * 
 * returns public key of length 128
 * */
string getPublicKey(string prv_key){
    EC_KEY* eckey = EC_KEY_new();
    EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey,ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    /* the private key value */
    BIGNUM* prv = BN_new();
    BN_hex2bn(&prv, prv_key.c_str());
    EC_POINT* pub = EC_POINT_new(ecgroup);

    /* calculate the public key */
    EC_POINT_mul(ecgroup, pub, prv, NULL, NULL, NULL);
    char* hexPKey = EC_POINT_point2hex( ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL );
    string pub_key(hexPKey);

    BN_free(prv);
    EC_POINT_free(pub);
    EC_GROUP_free(ecgroup); 
    EC_KEY_free(eckey);
    return pub_key;
}


/**
 * prv_key as above
 * Returns a pair of strings (R,S). Each string has length 64. 
 * */
pair<string, string> signMsg(string msg, string prv_key){
    EC_KEY* eckey = EC_KEY_new();
    EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey,ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BIGNUM* prv = BN_new();
    BN_hex2bn(&prv, prv_key.c_str());
    EC_POINT* pub = EC_POINT_new(ecgroup);

    /* calculate the public key */
    EC_POINT_mul(ecgroup, pub, prv, NULL, NULL, NULL);
    /* add the private & public key to the EC_KEY structure */
    EC_KEY_set_private_key(eckey, prv);
    EC_KEY_set_public_key(eckey, pub);
    unsigned char hash[32];
    sha256_digest(msg, hash);
    ECDSA_SIG* signature = ECDSA_do_sign(hash, 32, eckey);
    const BIGNUM* r = ECDSA_SIG_get0_r(signature);
    const BIGNUM* s = ECDSA_SIG_get0_s(signature);
    const char *r_st = BN_bn2hex(r);
    const char *s_st = BN_bn2hex(s);
    string r_str(r_st);
    string s_str(s_st);

    BN_free(prv);
    EC_POINT_free(pub);
    EC_GROUP_free(ecgroup); 
    EC_KEY_free(eckey);

    return make_pair(r_str, s_str);
    
}

bool verifySign(string msg, pair<string, string> sig, string pub_key){
    EC_KEY* eckey = EC_KEY_new();
    EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey,ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    BIGNUM *r = BN_new();
    BN_hex2bn(&r, sig.first.c_str());
    BIGNUM *s = BN_new();
    BN_hex2bn(&s, sig.second.c_str());
    ECDSA_SIG *signature = ECDSA_SIG_new();
    ECDSA_SIG_set0(signature, r, s);

    EC_POINT* pub = EC_POINT_new(ecgroup);
    EC_POINT_hex2point(ecgroup, pub_key.c_str(), pub, NULL);
    EC_KEY_set_public_key(eckey, pub);
    unsigned char hash[32];
    sha256_digest(msg, hash);
    int verify = ECDSA_do_verify(hash, 32, signature, eckey);
    // cout<<"verify in func = "<<verify<<endl;
    
    ECDSA_SIG_free(signature); //no need to free r and s individually
    EC_POINT_free(pub);
    EC_GROUP_free(ecgroup); 
    EC_KEY_free(eckey);
    
    if(verify == 1) return true;
    if(verify == 0) return false;
    if(verify == -1){
        cout<<"ERROR!\n";
    }
    return false;
}

void testSign(){
    string abhi = "Abhinav";
    pair <string, string> sig = signMsg(abhi, "6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C");
    string pub_key = getPublicKey("6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C");
    cout<<"Public key = "<<pub_key<<endl;
    cout<<"signature r: "<<sig.first<<"\nsignature s: "<<sig.second<<endl;

    bool verify = verifySign(abhi, sig, pub_key);
    if(verify) {cout<<"verified!\n";} else {cout<<"NOT verified!\n";}
    string sig_fraud = sig.first;
    sig_fraud[0] = '1';
    pair <string, string> new_sig = make_pair(sig_fraud, sig.second);
    verify = verifySign(abhi, new_sig, pub_key);
    if(verify) {cout<<"verified!\n";} else {cout<<"NOT verified!\n";}
}

//------- END OF DIGITAL SIGNATURE FUNCTIONS -------

//--------SERIALIZE and DESERIALIZE-------
/**
 * These are the functions we use to 
 * */

//----------------------------------------


int main(int argc, char **argv) {
    if (argc!=2){
		printf("Usage: [executable] [list_PORT]");
		return 0;
	}

    cout<<"LISTENING @ "<<argv[1]<<endl;
    cout<<"[IP] [PORT] [your message]\n";

    //--- for debugging
    blockchain::node n = {"127.0.0.1", 9003, getPublicKey("6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C")};
    known_peers.push_back(n);
    for (auto n :  known_peers){
        cout<<"public key: "<<n.pub_key<<endl;
    }
    json j = known_peers;
    blockchain::transaction t;
    
    cout<<"peer json: "<<j<<endl;
    blockchain::input in = {1, 0, "ginature1", "bignature"};
    blockchain::output out = {1.0, "04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326"};
    vector<blockchain::input> inputs = {in};
    vector<blockchain::output> outputs = {out};

    blockchain::transaction tx = {inputs, outputs};
    vector<blockchain::transaction> tx_vec = {tx};
    json trans_json = tx;
    json trans_vec_json = tx_vec;
    
    cout<<"transaction : "<<trans_json<<endl;
    cout<<"transaction vec: "<<trans_vec_json<<endl;
    return 0;
    //-----------------
    int port = atoi(argv[1]);
    int sockfd = init_listen_port(port);
    thread listener (listener_func, sockfd);
    
    

    while(1){
        cout<<"> ";       
        string ip = "127.0.0.1";
        char data[MAX];
        bzero(&data, MAX);
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