# ping_app
Ping CLI application
* The source code takes two arguments - IP address/hostname and ttl
* We can use the Makefile to compile the program, it will create an executable ping
	- Run make clean to clean up the existing objects and executables
* As we are creating Raw sockets, we need root permission to run the program
    - example1 : sudo ./ping google.com 64
    - example2 : sudo ./ping 8.8.8.8 255
