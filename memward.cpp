//
// Created by niki on 21.10.21.
//

#include<iostream>
#include <vector>
#include <dirent.h>
#include <cstring>
#include <csignal>
#include <algorithm>

int kill_process(pid_t pid) {
    return kill(pid, SIGHUP);
}

/**
 * Checks if a C string is a number
 * @param str input string
 * @return true if string is numeric, false otherwise
 */
static bool is_number(const char *str) {
    while (*str != '\0') {
        if (!isdigit(*str))
            return false;
        str++;
    }
    return true;
}


int main() {
    const std::string cmd_praefix = "memwars_";

    // Directory /proc, to read all process ids
    DIR *proc_dirf;
    // Entries of /proc
    struct dirent *entry;
    // File with the cmdline
    FILE *cmdline_file;
    // Helper variables
    char filename[1024], cmdline[2048];
    // Process ID
    pid_t pid;

    // List of all process IDs
    static std::vector<pid_t> process_ids;

    while (true) {

        // Open proc dir to get all process IDs
        proc_dirf = opendir("/proc");
        if (proc_dirf == NULL) {
            perror("Could not open /proc dir");
            exit(1);
        }
        // Read all entries (i.e. files, dirs) of /proc
        while ((entry = readdir(proc_dirf)) != NULL) {
#ifndef _DIRENT_HAVE_D_TYPE
    #error Cannot find dirent type. Use another linux ...
#endif
            // Entry is directory and the name is only a number (process ID)
            if (entry->d_type == DT_DIR && is_number(entry->d_name)) {
                // Check whether or not the command line includes cmd_praefix
                sprintf(filename, "/proc/%s/cmdline", entry->d_name);
                cmdline_file = fopen(filename, "r");
                pid = atoi(entry->d_name);
                if (cmdline_file == NULL || pid == 0) {
                    //perror("Could not open cmdline. Skipping entry.");
                    // Ignore error -- it is most likely none of our programs ...
                    continue;
                }
                // Add process ID to vector if it starts with cmd_praefix
                while (fgets(cmdline, sizeof(cmdline), cmdline_file)) {
                    if (strstr(cmdline, cmd_praefix.c_str()) != NULL) {
                        if (std::find(process_ids.begin(), process_ids.end(), pid) == process_ids.end()) {
                            process_ids.push_back(pid);
                        }
                        break;
                    } else {
                        if (std::find(process_ids.begin(), process_ids.end(), pid) != process_ids.end()) {
                            printf("Found illegal process. Try to kill process %d ...", pid);
                            printf("%d\n", kill_process(pid));
                            process_ids.erase(std::remove(process_ids.begin(), process_ids.end(), pid),
                                              process_ids.end());
                        }
                    }
                }
                fclose(cmdline_file);
            }
        }

        closedir(proc_dirf);
    }

}
