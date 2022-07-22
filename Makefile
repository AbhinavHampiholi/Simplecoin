targ:
	g++ -std=c++17 node.cpp -lpthread -lcrypto -o node
	g++ -std=c++17 genkeys.cpp -lpthread -lcrypto -o genkeys
clean:
	rm node
	rm genkeys