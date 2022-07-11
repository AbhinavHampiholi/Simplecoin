targ:
	g++ -std=c++17 node.cpp -lpthread -lcrypto -o node
clean:
	rm node