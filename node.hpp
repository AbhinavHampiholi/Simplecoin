#ifndef NODE_DECL_H
#define NODE_DECL_H

#include <bits/stdc++.h>
#include "json.hpp"
using namespace std;
using json = nlohmann::json;

namespace blockchain{
    typedef struct node{
        string ip;
        int port;
        string pub_key;
    } node;

    void to_json(json& j, const node& n) {
        j = json{{"ip", n.ip}, {"port", n.port}, {"pub_key", n.pub_key}};
    }

    void from_json(const json& j, node& n) {
        j.at("ip").get_to(n.ip);
        j.at("port").get_to(n.port);
        j.at("pub_key").get_to(n.pub_key);
    }

    typedef struct unsigned_input{
        int tx_id; //index of referenced transaction in the blockchain
        int op_index; //the output within that transaction that is being referenced
        string pub_key; //of the sender
        float value; //of the referenced transaction
    } unsigned_input;

    void to_json(json& j, const unsigned_input& i) {
        j = json{{"tx_id", i.tx_id}, {"op_index", i.op_index}
        ,  {"pub_key", i.pub_key}, {"value", i.value}};
    }
    void from_json(const json& j, unsigned_input& i) {
        j.at("tx_id").get_to(i.tx_id);
        j.at("op_index").get_to(i.op_index);
        j.at("pub_key").get_to(i.pub_key);
        j.at("value").get_to(i.value);
    }

    typedef struct input{
        unsigned_input ui;
        string sig_r; // the sender must sign the string ui with his private key to authorize
        string sig_s;
    } input;

    void to_json(json& j, const input& i) {
        j = json{{"ui", i.ui}, {"sig_r", i.sig_r}, {"sig_s", i.sig_s}};
    }
    void from_json(const json& j, input& i) {
        j.at("ui").get_to(i.ui);
        j.at("sig_r").get_to(i.sig_r);
        j.at("sig_s").get_to(i.sig_s);
    }

    typedef struct output{
        float value; //amount to be transferred
        string pub_key; //recipient
    } output;

    void to_json(json& j, const output& o) {
        j = json{{"value", o.value}, {"pub_key", o.pub_key}};
    }
    void from_json(const json& j, output& o) {
        j.at("value").get_to(o.value);
        j.at("pub_key").get_to(o.pub_key);
    }

    typedef struct transaction{
        vector <input> inputs;
        vector <output> outputs;
    } transaction;

    void to_json(json& j, const transaction& t) {
        j["inputs"] = t.inputs;
        j["outputs"] = t.outputs;
    }
    void from_json(const json& j, transaction& t) {
        j.at("inputs").get_to(t.inputs);
        j.at("outputs").get_to(t.outputs);
    }

    typedef struct block{
        string nonce; //A string such that SHA256(nonce+hash_prev+tx) has the target property
        string hash_prev; //hash of previous block
        transaction tx;
    } block;

    void to_json(json& j, const block& b) {
        j["nonce"] = b.nonce;
        j["hash_prev"] = b.hash_prev;
        j["tx"] = b.tx;
    }
    void from_json(const json& j, block& b) {
        j.at("nonce").get_to(b.nonce);
        j.at("hash_prev").get_to(b.hash_prev);
        j.at("tx").get_to(b.tx);
    }

    typedef struct envelope{
        node from;
        string subject;
        string data;
    } envelope;

    void to_json(json& j, const envelope& e) {
        j["from"] = e.from;
        j["subject"] = e.subject;
        j["data"] = e.data;
    }
    void from_json(const json& j, envelope& e) {
        j.at("from").get_to(e.from);
        j.at("subject").get_to(e.subject);
        j.at("data").get_to(e.data);
    }
}

#endif