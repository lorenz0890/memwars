// C++ headers
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <random>
#include <fstream>
// Dirty old C headers
#include <cstdio>
#include <cstdlib>
#include <cstring>
// Linux/Unix/POSIX headers
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

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

/**
 * Checks if a C string is a number
 * @param str input string
 * @return true if string is numeric, false otherwise
 */
static bool is_number(const char* str){
    while( *str != '\0' ){
        if(! isdigit(*str))
            return false;
        str++;
    }
    return true;
}

/**
 * Gets all process ids of which their execution path starts with cmd_praefix
 * @param cmd_praefix part execution path (needle)
 * @return vector of process IDs
 * @note Mixed C and C++ function
 */
std::vector<pid_t> get_valid_pids(const std::string& cmd_praefix = "memwars_"){
    // Directory /proc, to read all process ids
    DIR *proc_dirf;
    // Entries of /proc
    struct dirent *entry;
    // File with the cmdline
    FILE *cmdline_file;
    // Helper variables
    char filename[1024], cmdline[2048];
    // Vector with process ids
    std::vector<pid_t> process_ids;

    // Open proc dir to get all process IDs
    proc_dirf = opendir("/proc");
    if( proc_dirf == NULL ){
        perror("Could not open /proc dir");
        exit(1);
    }
    // Read all entries (i.e. files, dirs) of /proc
    while( (entry = readdir(proc_dirf)) != NULL ){
#ifndef _DIRENT_HAVE_D_TYPE
    #error Cannot find dirent type. Use another linux ...
#endif
        // Entry is directory and the name is only a number (process ID)
        if( entry->d_type == DT_DIR && is_number(entry->d_name) ){
            // Check whether or not the command line includes cmd_praefix
            sprintf(filename, "/proc/%s/cmdline", entry->d_name);
            cmdline_file = fopen(filename, "r");
            if(cmdline_file == NULL){
                //perror("Could not open cmdline. Skipping entry.");
                // Ignore error -- it is most likely none of our programs ...
                continue;
            }
            // Add process ID to vector if it starts with cmd_praefix
            while(fgets(cmdline, sizeof(cmdline),  cmdline_file)){
                if(strstr(cmdline, cmd_praefix.c_str()) != NULL){
                    //std::cout << "PID=" << atoi(entry->d_name) << ", self=" << getpid() << std::endl;
                    process_ids.push_back(atoi(entry->d_name));
                    break;
                }
            }
            fclose(cmdline_file);
        }
    }

    closedir(proc_dirf);

    return process_ids;
}

/**
 * Get list of memory mappings (addresses) per process
 * @param pids PIDs of the processes
 * @return Map of addresses per process
 */
std::map<int, std::vector<std::pair<std::string, std::string>>> get_memory_mapping(std::vector<pid_t>& pids){
    std::map<pid_t, std::vector<std::pair<std::string, std::string>>> map;
    std::ifstream procfile;
    std::string line;

    for(auto& pid : pids) {
        // get file name
        std::string filename = "/proc/"+ std::to_string(pid)+"/maps";

        // open proc file with memory map
        procfile.open(filename);
        while(std::getline(procfile, line)){
            std::string start_addr = line.substr(0, line.find('-'));
            std::string end_addr = line.substr(line.find('-')+1, line.find(' ')-line.find('-'));
            map[pid].push_back(std::make_pair(start_addr,end_addr));
        }

        procfile.close();
    }
    return map;
}

/**
 * Generate random data of size len from alphabet
 * @param len requested size of string
 * @return random data as string
 */
std::string make_payload(const size_t len) {
    static std::random_device rd;
    static std::mt19937 gen(rd());

    static const char alphabet[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    std::string tmp_s (len, 0);
    std::uniform_int_distribution<> dis(0, sizeof(alphabet) - 2); // -2 because: without \0 and from 0 to n-1
    for (size_t i = 0; i < len; ++i)
        tmp_s[i] = alphabet[dis(gen)];
    return tmp_s;
}

int main() {
    // root / sudo is required
    if( getuid() != 0 ){
        fprintf(stderr, "ERROR: You need root privileges to execute this program.\n");
        return EXIT_FAILURE;
    }

    // Wait before starting to kill, so that the process IDs can be registered by the daemon
    // You are NOT allowed to remove or edit this line!
    sleep(3);

    while(true){
        // 1. Hunt phase (select target process and adress range)
        // 1.1 Observe targets (get PIDs + memory mapping)
        std::vector<pid_t> pids = get_valid_pids();
        if( pids.size() < 2 ){
            std::cerr << "Error: No other process found yet. Skipping ...\n";
            sleep(1);
            continue;
        }
        std::map<pid_t, std::vector<std::pair<std::string, std::string>>> memory_map = get_memory_mapping(pids);

        // 1.2 Select target from observed targets (ensure we have valid memory mapping)
        // You might want to change the strategy of choosing the process ID or mamory apping from random
        // to something else or want to add some checks, ...
        pid_t pid = *select_randomly(pids.begin(), pids.end());
        while ( memory_map.find(pid) == memory_map.end() ){
            pid  = *select_randomly(pids.begin(), pids.end());
        }

        // 1.2.1 Select attack surface of selected target (which memory range we attack)
        // Maybe you want to choose another strategy for selecting the memory blocks or
        // you want to add some checks ...
        auto addr_rng = *select_randomly(memory_map[pid].begin(), (memory_map[pid].end()));
        std::string start_addr = addr_rng.first;
        std::string end_addr  = addr_rng.second;

        unsigned long start_value = std::strtoul(addr_rng.first.c_str(), NULL, 16);
        unsigned long end_value = std::strtoul(addr_rng.second.c_str(), NULL, 16);
        unsigned long len = end_value - start_value;

        // 2. Kill phase
        // Generate random data. You may change, if you want ...
        std::string payload = make_payload(len);

        //https://renenyffenegger.ch/notes/Linux/memory/read-write-another-processes-memory
        // 2.1 Acquire target
        char proc_mem[1024]; // Filename of memory file
        sprintf(proc_mem, "/proc/%d/mem", pid);
        printf("Opening %s, address is %ld\n", proc_mem, start_value);
        int fd_proc_mem = open(proc_mem, O_RDWR);
        if (fd_proc_mem == -1) {
            fprintf(stderr, "Could not open %s\n", proc_mem);
            //exit(1);
            continue;
        }
        char* buf = new char[len];
        /* IF YOU WANT TO READ THE VALUES OF THE MEMORY, YOU CAN DO IT LIKE THIS.
         * Feel free to do, if you want ...
        lseek(fd_proc_mem, start_value, SEEK_SET);
        read (fd_proc_mem, buf , len);
        printf("String at %ld in process %d is:\n", start_value, pid);
        printf("  %s\n", buf);
         */

        // 2.2 Attack target
        printf("\nNow, this string is modified\n");
        strncpy(buf, payload.c_str(), len);
        lseek(fd_proc_mem, start_value, SEEK_SET);
        if (write(fd_proc_mem, buf, len) == -1) {
            printf("Error while writing\n");
            // Eventually, another process has already killed this one,
            // this section cannot be written to or something else.
            // Try next section (next iteration), or try to fix ...
        }

        // 2.3 Clean up
        delete[] buf;
    }
}
