# Simplecoin
A simple node that can be run on multiple machines in the same network and maintain a blockchain of transactions

## Dependencies
- Linux
- [OpenSSL](https://www.openssl.org/source/) 

## What is SimpleCoin
Simplecoin is Bitcoin but simple. And bad. It is not secure or robust but does serve as a good introduction to the concepts used in Bitcoin. The genesis block of Simplecoin pays Gretoshi 25.0 Simps. Here is the keypair of Gretoshi  (it can also be found in the node_keys file).

private: `6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C`

public: `04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326`

The block reward for each newly mined block is 5.0 Simps. 

## Getting started
Navigate to the project directory and run make.
```console
foo@bar:~/Simplecoin$ make
```

Next, we'll run Gretoshi's node on port 9005
Open a terminal and start
```console
foo@bar:~/Simplecoin$ ./node 9005
```
When prompted for a private key, use Gretoshi's private key from above.
Next type `GENESIS` to add the first block to the chain.
Type `FUNDS` to make sure you have 25.0 Simps in this account.You should see something like this. 
```console
LISTENING @ 9005
Private key: 6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C
Socket successfully created...
Socket successfully binded...
Node listening...
> GENESIS
Added genesis!
> FUNDS
funds: 25
```

Next we'll open another account. Start another terminal instance and run node on port 9006.
On terminal 2
```console
foo@bar:~/Simplecoin$ ./node 9006
```
When prompted for a private key you can use one of the keys in `node_keys` such as `7D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C`.
Since this is a new peer into the network we'll need to obtain information about other peers in the network through Gretoshi (or any other known peer).
Do this using `INIT_PEERS` and enter Gretoshi's details (public key can be found in node_keys). You will also need to initialize blocks with the `INIT_BLOCKS` command and tell everyone who you are with the `BCAST_ID` commond (more on this later). You should see something like this on your second terminal.

```console
LISTENING @ 9006
Private key: 7D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C
Socket successfully created...
Socket successfully binded...
Node listening...
> INIT_PEERS
IP of friend: 127.0.0.1
PORT: 9005
public key: 04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326
> Initialised peers!

> INIT_BLOCKS
> Initialised blocks!

> BCAST_ID
```

Just for fun, let's add a third node to the network on say port 9007. Follow the same methodology as above but use a new private key such as `8A2EAC6A1F63FC105EBE9CA222151375683B733E9DDC9CA5B2485E202C55D25C`. On terminal 3 you should see something like

```console
LISTENING @ 9007
Private key: 8A2EAC6A1F63FC105EBE9CA222151375683B733E9DDC9CA5B2485E202C55D25C
Socket successfully created...
Socket successfully binded...
Node listening...
> INIT_PEERS
IP of friend: 127.0.0.1
PORT: 9005
public key: 04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326
> Initialised peers!

> INIT_BLOCKS
> Initialised blocks!

> BCAST_ID
```
Okay! we are now  ready to make our first transaction! Go to Gretoshi's terminal (terminal 1) and type `BCAST_TX`. When prompted for a recipient, add one of the public keys corresponding to terminals 2 or 3. The public keys can be found in the node_keys file. Let's say we want to send 10.0 Simps to terminal 2 guy. Enter his public key `04DFEC134530603832A31F8885EF01888884483D611F87A698213F168534EC06D85D21F7C85795435BC9A7F78190126CC6E52E050CBDFD43E27175FB1DF3E3DEF6` and transfer 10.0 Simps. Make sure the transaction looks good and type 'y' to  confirm it. Wait for a bit for the transaction to be added into a block by one of the miners (the other two terminals). You should see something like on Gretoshi's terminal.

```console
> BCAST_TX
Enter recepient public key: 04DFEC134530603832A31F8885EF01888884483D611F87A698213F168534EC06D85D21F7C85795435BC9A7F78190126CC6E52E050CBDFD43E27175FB1DF3E3DEF6
Enter amount to be transferred: 10.0
Your unsigned transation is 
{"inputs":[{"sig_r":"unsigned","sig_s":"unsigned","ui":{"op_index":0,"pub_key":"04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326","tx_id":0,"value":25.0}}],"outputs":[{"pub_key":"04DFEC134530603832A31F8885EF01888884483D611F87A698213F168534EC06D85D21F7C85795435BC9A7F78190126CC6E52E050CBDFD43E27175FB1DF3E3DEF6","value":10.0},{"pub_key":"04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326","value":15.0}]}
Do you wish to sign it and broadcast?(y/n)?
y
broadcasting...
> transaction verified!
Block verified!
```

In my case, terminal 2 was the miner that found the nonce first and therefore mined the block. Here is what terminal 2 looks like.
```console
> heard new tx!

> transaction verified!
Nonce found! after 34226 attempts
Hash of block is 05778c28f104e8c30328c0162ded3a59e257f337d979176ae4822e80aeed0000

transaction verified!
Block verified!
> Block mined!
```
Notice that it took this miner more than  34000 attempts to find a nonce such that the hash of the block ends in 0000. 
Okay so if terminal 2 mined the block, what should his funds be? They should be 15.0 because Gretoshi sent him 10.0 and the block reward is 5.0.
When I type `FUNDS` on terminal 2, indeed he has 15 Simps.

And that's it! You can continue sending money back and forth between nodes! With each transaction, 5 Simps get added to the currency supply. Because we are simple, we don't care about inflation (just like most governments).

## All the commands explained
We saw a few commands in the Getting Started section but there are more! Here is the comprehensive list.

### Being Gretoshi
If you are the Gretoshi node, you MUST run the `GENESIS` command.
- `GENESIS` : This must be run by Gretoshi. This is how Gretoshi initializes himself. It adds the hardcoded 'Genesis block' to Gretoshi's chain. 

### Initializing a new node
This MUST be done by all NON-GRETOSHI nodes. It also  must not be done by Gretoshi. Nodes can only join the network AFTER Gretoshi has already been initialized. 
- `INIT_PEERS` : This MUST be used by a new node while joining the network. It basically asks for details of a 'known' peer (Gretoshi is an obvious choice but not necessarily the only option) and then pings that node and asks him for all the peers that he knows.
- `INIT_BLOCKS` : This also MUST be used by a new node while joining the network. It asks one of the known peers for the current status of the blockchain. Once both the `INIT` commands are run, the new node is now upto speed with the rest of the network. 
- `BCAST_ID` : This is another must. It has to be run AFTER the above two commands. What it does is introduces you to all the other nodes in the network. Once this is run, everyone knows about your existence.


### Getting information
These commands are used for obtaining information about yourself.
- `LIST_PEERS`: Prints all your known peers.
- `LIST_BLOCKS`: Prints your entire blockchain. The output can get messy if the chain is long
- `NUM_BLOCKS`: Prints the length of your blockchain. Especially useful if the previous one is too messy.
- `HASH_LAST`: Prints the SHA256 hash of the last block in your chain. This can be used to verify if your chain is the same as everyone else's.
- `FUNDS`: Prints the number of Simps that you have.

### Making a transaction
- `BCAST_TX`: Used to send Simps. Refer to the Getting Started section for example usage.

## Customizing the node
There are some constants that you can change in `node.cpp`. 
If you want to make it easier or harder to mine blocks, change the `DIFFICULTY` and `DIFFICULTY_STRING` global constants. The higher the difficulty the harder it is to mine. Bear in mind that the length of the `DIFFICULTY_STRING` must be equal to the `DIFFICULTY`. So if you change the difficulty to 5, ensure that you change `DIFFICULTY_STRING` to `00000`. In order for a block to be valid, the suffix of its hash must equal the the `DIFFICULTY_STRING`.

You can also change the block reward (`BLOCK_RWD`).

## Some final thoughts and suggestions for improvement
The code as it stands is usable but has some obvious issues. I don't have the motivation to make this improvements right now but I might in the future. Here are some improvements that come to mind. 
- Clean up the code!!!! Use classes like a good c++  programmer and not structs. The reason I haven't done this yet is because I'm not sure if classes will work fine with the `json` library. I think it'll work fine. I'm just lazy. 
- Make `BCAST_TX` smarter. Right now it creates one MEGA transaction by referencing ALL valid transactions and giving you the rest as change. This is very dumb and unnecessary. For example,  If I  want to send you 0.1 Simps I don't need to reference all my previous unspent transactions. Just any one with a value higher than 0.1 will do.
- Deal with scale. Right now, we need to make one transaction, wait for it to be mined and turned into a block, and only then make another transaction. Or atleast that's what I think you need to do. If you make another tx before the first one is 'blocked'  it'll probably break something. Something is definitely going to break if there are > 10 nodes.