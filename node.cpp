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
 * List of command subjects
 * 
 * GENESIS
 * INIT_PEERS
 * INIT_PEERS_REPLY
 * LIST_PEERS
 * INIT_BLOCKS
 * INIT_BLOCKS_REPLY
 * LIST_BLOCKS
 * BCAST_ID
 * BCAST_TX
 * 
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
#define  MAX 4086
using namespace std;
using json = nlohmann::json;

int DIFFICULTY = 5;
string DIFFICULTY_STRING = "00000";
vector <blockchain::node> known_peers;
vector <blockchain::block> chain;
vector <blockchain::transaction> unblocked_tx;
blockchain::node me;
string priv_key;

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
 * returns true if the outputs[op_index] in chain[bid] has not
 * yet been referenced anywhere on the blockchain so far and therefore is unspent
 * */
bool check_if_unspent(int bid, int op_index){
    int l = chain.size();
    for (int i = bid; i<l; i++){
        auto [nonce, hash_prev, tx] = chain[i];
        for(auto in : tx.inputs){
            if(in.ui.tx_id == bid && in.ui.op_index == op_index) return false;
        }
    }
    return true;
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

bool verify_transaction(blockchain::transaction tx){
    //a transaction is valid iff 
    // 1. Sum input values = Sum output values
    // 2. All inputs reference unspent transactions on the blockchain
    // 3. All inputs are signed by the sender 
    float inp_sum = 0.0;
    float out_sum = 0.0;
    for (auto i : tx.inputs){
        inp_sum += i.ui.value;
        if(!check_if_unspent(i.ui.tx_id, i.ui.op_index)) {
            cout<<"references a spent transaction!\n";
            return false;
        }
        json js_ui = i.ui;
        stringstream data_str; 
        data_str << js_ui;
        string data_s = data_str.str();
        if(!verifySign(data_s, make_pair(i.sig_r, i.sig_s), i.ui.pub_key)){
            cout<<"Invalid signature!\n";
            return false;
        }
    }
    for (auto o : tx.outputs){
        out_sum += o.value;
    }

    if(inp_sum != out_sum){
        cout<<"transaction inputs don't match outputs\n";
        return false;
    }
    cout<<"transaction verified!\n";
    return true;
}

//------- END OF DIGITAL SIGNATURE FUNCTIONS -------

//--------SERIALIZE and DESERIALIZE-------
/**
 * These are the functions we use to 
 * */

//----------------------------------------



void sendTo(string ip, int port, const char *data){
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

void msgSender(blockchain::envelope env, blockchain::node to){
    auto [ip, port, pub_key] = to;
    json js = env;
    stringstream data_str; 
    data_str << js;
    string data_s = data_str.str();
    if(data_s.length() >= MAX){
        cout<<"MSG TOO LONG\n";
        return;
    }
    sendTo(ip, port, data_s.c_str());
}

/**
 * Broadcasts envelope to all known peers
 * */
void msgBroadcaster(blockchain::envelope env){
    for(auto peer : known_peers){
        if(peer.pub_key != me.pub_key) msgSender(env, peer);
    }
}

/**
 * This guy needs work. rand() is a terrible random  number generator.
 * */
std::string gen_random(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}

blockchain::block find_nonce(blockchain::transaction tx){
    auto prev_block = chain[chain.size()-1];
    json js_prev = prev_block;
    stringstream prev_block_stream;
    prev_block_stream << js_prev;
    string prev_block_str = prev_block_stream.str();
    string hash_prev = sha256(prev_block_str);

    json js_tx = tx;
    stringstream tx_stream;
    tx_stream << js_tx;
    string tx_str = tx_stream.str();
    int tries = 0;
    while(true){
        string nonce = gen_random(64);
        tries++;
        blockchain::block trial_blk= {nonce, hash_prev, tx};
        json trial_js = trial_blk;
        stringstream trial_stream;
        trial_stream << trial_js;
        string trial = trial_stream.str();
        if(sha256(trial).substr(64 - DIFFICULTY) == DIFFICULTY_STRING){
            cout<<"Nonce found! after "<<tries<<" attempts\n";
            cout<<"Hash of block is "<<sha256(trial)<<endl;
            cout<<trial_js;
            return trial_blk;
        }
        if(tries%10000==0){
            cout<<"Nonces tried: "<<tries<<endl;
        }
    }
}

bool verify_block(blockchain::block blk){
    //fill this in later!
    json blk_js = blk;
    stringstream blk_stream;
    blk_stream << blk_js;
    string blk_str = blk_stream.str();
    if(sha256(blk_str).substr(64-DIFFICULTY) != DIFFICULTY_STRING) {
        cout<<"incorrect nonce! invalid block\n";
        return false;
    }
    
    json blk_prev = chain[chain.size()-1];
    stringstream blk_prev_stream;
    blk_prev_stream << blk_prev;
    string blk_prev_str = blk_prev_stream.str();
    if(sha256(blk_prev_str) != blk.hash_prev) {
        cout<<"incorrect prev hash! Invalid block\n";
        return false;
    }

    if(!verify_transaction(blk.tx)){
        cout<<"invalid transaction! Invalid block\n";
        return false;
    }
    cout<<"Block verified!\n";
    return true;
}

void miner_func(){
    while(true){
        sleep(1); //unneccesary
        if(unblocked_tx.size()>0){
            int chain_length = chain.size();
            blockchain::block newBlock = find_nonce(unblocked_tx[0]);
            chain.push_back(newBlock);
            cout<<"Block mined!\n";
            //Later check if you actually mined first before broadcasting
            json block_js = newBlock;
            stringstream data_str;
            data_str << block_js;
            string data_s = data_str.str();
            blockchain::envelope new_blk_env = {me, "NEW_BLOCK", data_s};
            msgBroadcaster(new_blk_env);
            unblocked_tx.erase(unblocked_tx.begin()); //just erase the tx that was mined
        }
    }
}

void msgHandler(blockchain::envelope env){
    auto [from, subject, data] = env;
    json js  = json::parse(data);
    if(subject == "INIT_PEERS"){
        // cout<<"inside init_peers\n";
        json js_reply = known_peers;
        // cout<<"json reply ready...\n";
        stringstream data_str; 
        data_str << js_reply;
        string data_s = data_str.str();
        blockchain::envelope env_reply = {me, "INIT_PEERS_REPLY", data_s};
        msgSender(env_reply, from);
        known_peers.push_back(from);
    }
    else if(subject == "INIT_PEERS_REPLY"){
        vector <blockchain::node> new_peers = js.get<vector<blockchain::node>>();
        for( auto n : new_peers){
            known_peers.push_back(n);
        }
        cout<<"Initialised peers!\n> ";
    }
    else if(subject == "INIT_BLOCKS"){
        json js_reply = chain;
        stringstream data_str; 
        data_str << js_reply;
        string data_s = data_str.str();
        blockchain::envelope env_reply = {me, "INIT_BLOCKS_REPLY", data_s};
        msgSender(env_reply, from);
    }
    else if(subject == "INIT_BLOCKS_REPLY"){
        vector <blockchain::block> new_blocks = js.get<vector<blockchain::block>>();
        for( auto n : new_blocks){
            chain.push_back(n);
        }
        cout<<"Initialised blocks!\n> ";
    }
    else if(subject == "INTRO"){
        bool to_push = true;
        for(auto n : known_peers){
            if(n.pub_key == from.pub_key) to_push = false;
        }
        if(to_push) known_peers.push_back(from);
    }
    else if(subject == "NEW_TX"){
        cout<<"heard new tx!\n";
        cout<<data<<endl;
        blockchain::transaction tx =  js.get<blockchain::transaction>();
        if(verify_transaction(tx)){
            unblocked_tx.push_back(tx);
        }
    }
    else if(subject == "NEW_BLOCK"){
        cout<<"Heard new block!\n";
        cout<<data<<endl;
        blockchain::block new_block = js.get<blockchain::block>();
        if(verify_block(new_block)) {
            chain.push_back(new_block);
        }
    }
    else{
        cout<<"RECEIVED UNKNOWN MESSAGE: "<<subject<<endl;
    }
}



vector<blockchain::input>sign_inputs(string private_key, vector<blockchain::input>unsigned_inp){
    vector<blockchain::input> signed_inputs;
    for(auto inp : unsigned_inp){
        json js_ui = inp.ui;
        // cout<<"json reply ready...\n";
        stringstream data_str; 
        data_str << js_ui;
        string data_s = data_str.str();
        auto signed_pair = signMsg(data_s, private_key);
        signed_inputs.push_back({inp.ui, signed_pair.first, signed_pair.second});
    }
    return signed_inputs;
}   

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

        string buffString(buffComm);
        // cout<<"REC: "<<buffString<<endl;
        json js = json::parse(buffString);
        // cout<<"json :"<<js<<endl;
        blockchain::envelope env = js.get<blockchain::envelope>();
        // cout<<"got envelope...\n";
        msgHandler(env);
    }

}

void commandHandler(string cmd){
    if(cmd == "INIT_PEERS\n"){
        string ip, pub_key;
        int port;
        cout<<"IP of friend: ";
        cin>>ip;
        cout<<"PORT: ";
        cin>>port;
        cout<<"public key: ";
        cin>>pub_key;
        blockchain::node to = {ip, port, pub_key};
        blockchain::envelope env = {me, "INIT_PEERS", "{}"};
        msgSender(env, to);
    }
    else if(cmd == "LIST_PEERS\n"){
        json js = known_peers;
        cout<<js<<endl;
        cout<<"> ";
    }
    else if(cmd == "GENESIS\n"){
        //You are the first node
        //Add genesis block to the chain
        blockchain::unsigned_input gen_in_unsigned = {-1, -1, "somepubkey", 25.0};
        blockchain::input gen_in = {gen_in_unsigned, "genesis", "genesis"};
        blockchain::output gen_out = {25.0, "04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326"};
        vector <blockchain::input> gen_ins = {gen_in};
        vector<blockchain::output> gen_outs = {gen_out};
        blockchain::transaction tx = {gen_ins, gen_outs};
        blockchain::block gen_blk = {"nonsense", "nohash", tx};

        chain.push_back(gen_blk);
        cout<<"Added genesis!\n";
    }
    else if(cmd == "INIT_BLOCKS\n"){
        //Must be called only AFTER init peers
        blockchain::node to = known_peers[1]; //this should be fine since there will be atleast one other peer
        blockchain::envelope env = {me, "INIT_BLOCKS", "{}"};
        msgSender(env, to);
    }
    else if(cmd == "LIST_BLOCKS\n"){
        json js = chain;
        cout<<js<<endl;
    }
    else if(cmd == "BCAST_ID\n"){
        blockchain::envelope env = {me, "INTRO", "{}"};
        msgBroadcaster(env);
    }
    // This is a terrible way to make new transactions it is way too naive. Change it.
    else if(cmd == "BCAST_TX\n"){
        cout<<"Enter your public key: ";
        string sender_pubkey;
        cin>>sender_pubkey;
        cout<<"Enter recepient public key: ";
        string rec_pubkey;
        cin>>rec_pubkey;
        cout<<"Enter amount to be transferred: ";
        float amt;
        cin>>amt;
        float total_amt = 0.0;
        vector<blockchain::input> new_unsigned_inputs;
        for (int i = 0; i<chain.size(); i++){
            auto [nonce, hash_prev, tx] = chain[i];
            for(int j = 0; j<tx.outputs.size(); j++){
                if(tx.outputs[j].pub_key==sender_pubkey && check_if_unspent(i, j)) {
                    total_amt+=tx.outputs[j].value;
                    blockchain::unsigned_input ui;
                    ui = {i, j, sender_pubkey, tx.outputs[j].value};
                    //Just push all possible inputs into the tx!? unnecessary
                    new_unsigned_inputs.push_back({ui, "unsigned", "unsigned"});
                }
            }
        }
        if(total_amt < amt){
            cout<<"Insufficient funds. Current account balance: "<<total_amt<<endl;
        }
        else{
            vector<blockchain::output>outputs;
            blockchain::output to_rec, change;
            to_rec = {amt, rec_pubkey};
            change = {total_amt-amt, sender_pubkey};
            outputs.push_back(to_rec);
            outputs.push_back(change);
            blockchain::transaction unsigned_tx = {new_unsigned_inputs, outputs};
            json j_us = unsigned_tx;
            cout<<"Your unsigned transation is "<<endl;
            cout<<j_us<<endl;
            cout<<"Do you wish to sign it and broadcast?(y/n)?\n";
            string conf;
            cin>>conf;
            if(conf == "y"){
                // cout<<"creating tx...\n";
                auto signed_inputs = sign_inputs(priv_key, new_unsigned_inputs);
                blockchain::transaction signed_tx = {signed_inputs, outputs};
                json js_tx = signed_tx;
                // cout<<"json reply ready...\n";
                stringstream data_str; 
                data_str << js_tx;
                string data_s = data_str.str();
                blockchain::envelope env =  {me, "NEW_TX", data_s};
                cout<<"broadcasting...\n";
                msgBroadcaster(env);
            }
            else{
                cout<<"exiting transaction...\n";
            }
        }
    }
    else{
        cout<<"UNKNOWN COMMAND "<<cmd;
    }
}

int main(int argc, char **argv) {
    if (argc!=2){
		printf("Usage: [executable] [list_PORT]");
		return 0;
	}
    int port = atoi(argv[1]);
    cout<<"LISTENING @ "<<argv[1]<<endl;
    // cout<<"[IP] [PORT] [your message]\n";
    cout<<"Private key: ";
    cin>>priv_key;
    me.ip = "127.0.0.1";
    me.port = port;
    me.pub_key = getPublicKey(priv_key);
    known_peers.push_back(me);

    //--- for debugging
    // blockchain::node n = {"127.0.0.1", 9003, getPublicKey("6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C")};
    // known_peers.push_back(n);
    // blockchain::node n1 = {"127.0.0.1", 9004, getPublicKey("7D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C")};
    // known_peers.push_back(n1);
    // for (auto n :  known_peers){
    //     cout<<"public key: "<<n.pub_key<<endl;
    // }
    // return 0;
    // json j = known_peers;
    // blockchain::transaction t;
    
    // cout<<"peer json: "<<j<<endl;
    // blockchain::input in = {1, 0, "ginature1", "bignature"};
    // blockchain::output out = {1.0, "04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326"};
    // vector<blockchain::input> inputs = {in};
    // vector<blockchain::output> outputs = {out};

    // blockchain::transaction tx = {inputs, outputs};
    // vector<blockchain::transaction> tx_vec = {tx};
    // json trans_json = tx;
    // json trans_vec_json = tx_vec;

    // cout<<"transaction : "<<trans_json<<endl;
    // cout<<"transaction vec: "<<trans_vec_json<<endl;
    // return 0;
    //-----------------
    int sockfd = init_listen_port(port);
    thread listener (listener_func, sockfd);
    thread miner (miner_func);

    while(1){
        cout<<"> ";       
        char data[MAX];
        bzero(&data, MAX);
        fgets(data, 900, stdin);
        // cin>>ip>>port>>data;
        if(port==0){
            close(sockfd);
            exit(0);
        }
        string command(data);
        commandHandler(command);
    }
    close(sockfd); 
    return 0;
}