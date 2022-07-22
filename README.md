# Simplecoin
A simple node that can be run on multiple machines in a network and maintain a blockchain of transactions

## Dependencies
- A Linux runtime.
- [OpenSSL](https://www.openssl.org/source/) 

## Getting started
Navigate to the project directory and run make.
```console
foo@bar:~/Simplecoin$ make
```

Next, open two terminals and start a node on each terminal.
On terminal 1
```console
foo@bar:~/Simplecoin$ ./node 9005
```

On terminal 2
```console
foo@bar:~/Simplecoin$ ./node 9006
```

Terminal 1 will be the genesis node. 
Type the following commands on terminal 1. The private key below can be found in the node_keys file in the project.
```console
LISTENING @ 9005
Private key: 6D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C
Socket successfully created...
Socket successfully binded...
Node listening...
> UNKNOWN COMMAND 
> GENESIS
Added genesis!
```

Now go to terminal 2 and run the following
```console
LISTENING @ 9006
Private key: 7D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C
Socket successfully created...
Socket successfully binded...
Node listening...
> UNKNOWN COMMAND 
> INIT_PEERS
IP of friend: 127.0.0.1
PORT: 9005
public key: 04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326
> UNKNOWN COMMAND 
> Initialised peers!

> UNKNOWN COMMAND 
> INIT_BLOCKS
> Initialised blocks!
```

Now go back to terminal 1 and broadcast a transaction!
```console
> BCAST_TX
Enter your public key: 04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326
Enter recepient public key: 04DFEC134530603832A31F8885EF01888884483D611F87A698213F168534EC06D85D21F7C85795435BC9A7F78190126CC6E52E050CBDFD43E27175FB1DF3E3DEF6
Enter amount to be transferred: 10.0
Your unsigned transation is 
{"inputs":[{"sig_r":"unsigned","sig_s":"unsigned","ui":{"op_index":0,"pub_key":"04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326","tx_id":0,"value":25.0}}],"outputs":[{"pub_key":"04DFEC134530603832A31F8885EF01888884483D611F87A698213F168534EC06D85D21F7C85795435BC9A7F78190126CC6E52E050CBDFD43E27175FB1DF3E3DEF6","value":10.0},{"pub_key":"04199216BE19D346E73195C9D2BC13D3B996124E287EBE433DB6B040B975192FB35653C7FBA678896902838121970314106A34719AAD96C868C6D160DE43A4B326","value":15.0}]}
Do you wish to sign it and broadcast?(y/n)?
y
broadcasting...
> UNKNOWN COMMAND 
> Heard new block!
```

More later! 
