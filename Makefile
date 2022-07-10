targ:
	g++ node.cpp -lpthread -lcrypto -o node
clean:
	rm node