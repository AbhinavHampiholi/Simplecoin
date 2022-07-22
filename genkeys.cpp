
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

int main(){
    cout<<"Enter private key: ";
    string privKey;
    cin>>privKey;
    cout<<"Public key is: ";
    cout<<getPublicKey(privKey);
    return 0;
}