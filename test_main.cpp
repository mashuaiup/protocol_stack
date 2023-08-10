#include "stack.h"
#include <iostream>
#include <thread>
using namespace std;
int main(int argc, char* argv[]){
    start(argc, argv);
    thread udp(udp_server_entry, argv);
    thread tcp(tcp_server_entry, argv);
    
    udp.join();
    tcp.join();
    
}