#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <cerrno>
#include <arpa/inet.h>
#include<vector>



std::string forward_address; 
std::string parseName(const char* buffer, int& offset, int maxLen) {
    std::string name;
    while (offset < maxLen) {
        uint8_t len = buffer[offset++];
        if (len == 0) {
            name .push_back(0);
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            // pointer
            uint16_t ptr;
            memcpy(&ptr, buffer + offset - 1, 2);
            offset++;
            ptr = ntohs(ptr) & 0x3FFF;
            int dummy = ptr;
            return name+parseName(buffer, dummy, maxLen);
        } else {
            name += len;
            for (int i = 0; i < len; ++i) {
                name += buffer[offset++];
            }
        }
    }
    return name;
}

class header{
    private:
    std::string res;
    public:
    header(){
        res.resize(12,0);
    }
    void set_pid(uint16_t pid){
       res[0] = (pid >> 8) & 0xFF;
res[1] = pid & 0xFF;

    }
    void set_flags(uint16_t flags){
       res[2] = (flags >> 8) & 0xFF;
res[3] = flags & 0xFF;

    }
    void set_qdcount(uint16_t qcnt){
       res[4] = (qcnt >> 8) & 0xFF;
res[5] = qcnt & 0xFF;

    }
    void set_ancount(uint16_t acnt){
        res[6] = (acnt >> 8) & 0xFF;
res[7] = acnt & 0xFF;

    }
    void set_nscount(uint16_t auth_cnt){
       res[8] = (auth_cnt >> 8) & 0xFF;
res[9] = auth_cnt & 0xFF;

    }
    void set_arcount(uint16_t addt_cnt){
       res[10] = (addt_cnt >> 8) & 0xFF;
res[11] = addt_cnt & 0xFF;

    }
    std::string get_packet(){
        return res;
    }
};
int main(int argc ,char *argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if(argc>=3) forward_address=argv[2];

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

      // Uncomment this block to pass the first stage
   int udpSocket;
   struct sockaddr_in clientAddress;
//
   udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
   if (udpSocket == -1) {
       std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
       return 1;
   }

   // Since the tester restarts your program quite often, setting REUSE_PORT
   // ensures that we don't run into 'Address already in use' errors
   int reuse = 1;
   if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
       std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
       return 1;
   }

   sockaddr_in serv_addr = { .sin_family = AF_INET,
                             .sin_port = htons(2053),
                             .sin_addr = { htonl(INADDR_ANY) },
                           };

   if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
       std::cerr << "Bind failed: " << strerror(errno) << std::endl;
       return 1;
   }

   int bytesRead;
   char buffer[512];
   socklen_t clientAddrLen = sizeof(clientAddress);

   while (true) {
       // Receive data
       bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
       if (bytesRead == -1) {
           perror("Error receiving data");
           break;
       }

       buffer[bytesRead] = '\0';
       std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;
       //parsing header
       uint16_t flags,flags2;
       uint16_t pid;
       uint16_t qcnt;
       memcpy(&pid,buffer,sizeof(pid));
       pid=ntohs(pid);
       memcpy(&flags,buffer+2,sizeof(flags));
       memcpy(&flags2,buffer+2,sizeof(flags2));
       flags|=htons(static_cast<uint16_t>(1 << 15));
       flags=ntohs(flags);
       flags2=ntohs(flags2);
       memcpy(&qcnt,buffer+4,sizeof(qcnt));
       qcnt = ntohs(qcnt);
       uint8_t opcode = (flags >> 11) & 0x0F;
       if(opcode!=0){
        flags=(flags|0x04);
       }
       flags=(flags|0x8000);


       // Create an empty response
       header* res_packet=new header;

       res_packet->set_pid(pid);
       res_packet->set_flags(flags);

       header* res_packet2=new header;

       res_packet2->set_pid(pid);
       res_packet2->set_flags(flags2);
       res_packet2->set_qdcount(1);
       std::string head2=res_packet2->get_packet();

       //question
      std::vector<std::string>questions,answers;
       int offset = 12;  // DNS header is 12 bytes


      while(qcnt){
        std::string qs,ans;
       
uint32_t ttl = htonl(60);  // ✅ Use htonl not htons for TTL (it's 4 bytes)
uint16_t d_length = htons(4);
uint8_t data[] = {8, 8, 8, 8};  // IP address

auto buildAnswer = [&](const std::string &name) {
    std::string a = name;
    uint16_t type = htons(1);   // Type A
    uint16_t clas = htons(1);   // IN
    a.append(reinterpret_cast<const char*>(&type), 2);
    a.append(reinterpret_cast<const char*>(&clas), 2);
    a.append(reinterpret_cast<const char*>(&ttl), 4);
    a.append(reinterpret_cast<const char*>(&d_length), 2);
    a.append(reinterpret_cast<const char*>(data), 4);
    return a;
};


std::string name = parseName(buffer, offset, bytesRead);

qs = name;
qs.append(buffer + offset, 4); // QTYPE + QCLASS
ans=buildAnswer(name);
offset += 4;

questions.push_back(qs);
answers.push_back(ans);
qcnt--;
      }





    

// Final response
std::string res;
std::vector<std::string>answers2;
uint16_t cnt_a=0;
if (!forward_address.empty()) {
    
    int ind = forward_address.find(':');
    std::string ip = forward_address.substr(0, ind);
    int port = std::stoi(forward_address.substr(ind + 1));

    int c_s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in server_add{};
    server_add.sin_family = AF_INET;
    server_add.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_add.sin_addr);

    for (const std::string& question : questions) {
        
        std::string req2 = head2 + question;
        sendto(c_s, req2.data(), req2.size(), 0, reinterpret_cast<sockaddr*>(&server_add), sizeof(server_add));

        char buf2[512];
        sockaddr_in recv_addr{};
        socklen_t addr_len = sizeof(recv_addr);
        int bytes_received = recvfrom(c_s, buf2, sizeof(buf2), 0, reinterpret_cast<sockaddr*>(&recv_addr), &addr_len);
         std::cout << "Received2 " << bytes_received << " bytes2: " << buf2 << std::endl;

       int ans_offset = 12;
       uint16_t an_cnt;
       memcpy(&an_cnt,buf2+6,2);
       an_cnt=ntohs(an_cnt);
       cnt_a+=an_cnt;
       std::cout<<an_cnt<<std::endl;
       if(an_cnt>=1){

        parseName(buf2, ans_offset, bytes_received);
ans_offset += 4;  // QTYPE + QCLASS

if (ans_offset> bytes_received) {
    std::cerr << "Buffer too small for QTYPE+QCLASS\n";
}


std::string an(buf2 + ans_offset, bytes_received - ans_offset);
answers2.push_back(an);
       }
// question section from forwarding server

    }

    close(c_s);

    res_packet->set_qdcount((uint16_t)questions.size());
    res_packet->set_ancount((uint16_t)answers2.size());
    std::string head = res_packet->get_packet();
    res = head ;
for(int i=0;i<questions.size();i++){
    res+=questions[i];
}
    for (const std::string& ans : answers2) {
        res += ans;
    }
    

}

else{
    //std::cout<<(int)answers.size()<<std::endl;
res_packet->set_qdcount((uint16_t)questions.size());
    res_packet->set_ancount((uint16_t)answers.size());
    std::string head = res_packet->get_packet();
    res = head ;
for(int i=0;i<questions.size();i++){
    res+=questions[i];
}
    for (const std::string& ans : answers) {
        res += ans;
    }
    
}





       // Send response
       if (sendto(udpSocket, res.data(), res.size(), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
           perror("Failed to send response");
       }
   }

   close(udpSocket);

    return 0;
}
