/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <algorithm> 

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

using namespace std;
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t ecall_status;

// struct for file info
typedef struct _real
{
    char name[64]; // file name limited to 30B
    char attr; // append only? immutable?
    int directory; // 0, 1, 3, 5, 7, 10
}real;

typedef struct _verify{
    int directory_num;
    int mode; // mode:1 (re_read), other: new read
}verify;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

#define ENC_SIZE 633

pthread_attr_t attr;
pthread_t comp_clock;
pthread_t file_receive;
pthread_t get_localt;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // mutex lock for ECALL
pthread_cond_t cond;

char time_info[10]; // save local time here

// used for calculating an execution time of verify & delete
clock_t verify_start, verify_end;
clock_t delete_start, delete_end;

// used for calculating an execution time of verify & delete
double verify_cpu_time;
double delete_cpu_time;

unsigned char*ret_encrypted_data;
int ret_hash_value;

vector<vector<unsigned char *> > secure_file[5]; // all file inforamtion is saved in this vector ([0]: directory 0, [1]: directory 1, [2]: directory 3...)

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};


/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
    
    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    
    return 0;
    
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

void ocall_print_hex(unsigned char *str, int len)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
     printf("size : %d\n", len);
     for(int i = 0; i < len; i++){
         printf("%.2x", str[i]);
     }
     printf("\n");
}

void ocall_pass_string(unsigned char *str, int hash_value, int dir_index)
{
    //factory fucntion
    ret_encrypted_data = (unsigned char*)malloc(ENC_SIZE);
    memset(ret_encrypted_data, 0, ENC_SIZE);
    memcpy(ret_encrypted_data, str, ENC_SIZE);
    ret_hash_value = hash_value;
    secure_file[dir_index][hash_value].push_back(ret_encrypted_data);
    //jinhoon
    //memcpy passed value
}

// re-read file attribute and retention time(xattr) from worm_files/.. and save those into enclave
void *scan_dir(void *select){  // 원래는 *dir_num을 받았음
    
    // etc variables for reading file attribute and extended attribute from files stored in worm_files/
    int dir_num;
    int ret, i, j, fd, fattr, suc; // file attribute(a, i) read from file is saved in fattr
    char path[60]; // for directory path.. ex) /home/soteria/worm_files/3/append
    char tmp[120]; // for full file path.. ex) /home/soteria/worm_files/3/append/test3.txt
    
    char get_ret[16]; // retention time read from file is saved in get_ret
    char attr; // file attribute(a, i) that is passed as an argument to save_file_info (ECALL)
    int retention; // file retention time that is passed as an argument to save_file_info (ECALL)
    
    // variables for reading files from directory
    DIR *mydir;
    struct dirent *myfile;
    struct stat mystat;
    const char *default_path = "/home/lass/worm_files";
    
    verify *choose;
    
    choose = (verify *)malloc(sizeof(verify));
    
    memcpy(choose, (verify *)select, sizeof(verify));
    
    dir_num = choose->directory_num; // directory num
    
    LOG_V("dir num is %d\n", dir_num);
    
    // check append directory and immutable directory
    for(i=0; i<2; i++){
        
        memset(path, 0, 60); // initialize file path array
        
        // make path for append directory
        if(i==0){
            sprintf(path, "%s/%d/append", default_path, dir_num);
        }
        
        // make path for immutable directory
        else if(i==1){
            sprintf(path, "%s/%d/immutable", default_path, dir_num);
        }
        
        mydir = opendir(path);
        
        // span directory
        while((myfile = readdir(mydir)) != NULL){
            // exclude . and ..
            if(strcmp(myfile->d_name, ".") != 0 && strcmp(myfile->d_name, "..") != 0){
                
                sprintf(tmp, "%s/%s", path, myfile->d_name);
                
                ret = getxattr(tmp, "trusted.retention", get_ret, 9); // get retention time
                
                if(ret<0)
                    printf("Thread %d error with file getxattr %s: %s \n", dir_num, tmp, strerror(errno));
                
                fd = open(tmp, O_RDONLY);
                
                if(fd<0)
                    printf("Thread %d error with file open %s: %s \n", dir_num, tmp, strerror(errno));
                
                ioctl(fd, FS_IOC_GETFLAGS, &fattr); // get file attribute
                
                if(fattr == 0x80020) // file attribute is append only
                    attr = 'a';
                
                else if(fattr == 0x80010) // file attribute is immutable
                    attr = 'i';
                
                close(fd);
                
                retention = atoi(get_ret);
                
                LOG_V("Thread %d: file name is %s\n", dir_num, myfile->d_name);
                LOG_V("retention: %d, attr: %c\n", retention, attr);
                
                // save file name, attr, retention into Enclave
                if(choose -> mode == 1){
                    ecall_status = save_file_info(global_eid, &ret, myfile->d_name, &attr, &dir_num, &retention, &(choose -> mode));
                    //jinhoon
                    //여기서 리턴된 sealed_data를 저장하는 코드가 필요
                    
                    //+ 수정 pass_string 에서 아예 push_back 또한 해줌
                    
                    if(ret==1)
                        LOG_V("re-saved file %s metadata into enclave\n", myfile->d_name);
                }
                
                else if(choose -> mode != 1){ // verify
                    
                    int len = strlen(myfile->d_name);
                    int hash_value = 0;
                    for(int i = 0; i < len; i++){
                        hash_value += myfile->d_name[i];
                    }
                    hash_value %= 100;
                    //jinhoon
                    //make hash value
                    
                    //안에서 돌리던 이터레이션을 여기서 돌게 해야함
                    //[dir_num][hash_value]가 벡터인데 이를 쭉 확인해야함
                    int dir_index = 0;
                    if(dir_num == 1)
                        dir_index = 0;
                    if(dir_num==3)
                        dir_index = 1;
                    else if(dir_num==5)
                        dir_index = 2;
                    else if(dir_num==7)
                        dir_index = 3;
                    else if(dir_num==10)
                        dir_index = 4;
                    for(auto&tmp : secure_file[dir_index][hash_value]){
                        ecall_status = verifier(global_eid, &suc, myfile->d_name, &attr, &retention, &dir_num, tmp);
                    }
                    //ecall_status = verifier(global_eid, &suc, myfile->d_name, &attr, &retention, &dir_num);
                    
                    
                    
                    // something changed.. something bad happened..
                    if(suc == -1){
                        printf(SEPARATOR);
                        printf("WARNING\nWARNING\nWARNING\n");
                        printf("file error in thread %d, file: %s\n", dir_num, myfile->d_name);
                        printf("WARNING\nWARNING\nWARNING\n");
                        printf(SEPARATOR);
                    }
                    
                }
                
                
                memset(tmp, 0, 120);
                
            }
            
        }
        
        closedir(mydir);
    }
    
    
    pthread_exit(NULL);
}


void verify_file(int flag) // flag:1 => re-read file meatdata, flag:2 => verify file metadata
{
    // five directories; 1, 3, 5, 7, 10
    int dir_num[5] = {1, 3, 5, 7, 10};
    pthread_t dir[5]; // for file verifying
    pthread_t re_read[5]; // for re-reading file attrs and retention time from worm_files
    pthread_attr_t attr;
    
    int i, ret, ret2;
    verify two_mode[5];
    
    pthread_attr_init(&attr);
    
    if(flag ==1){ // re_read mode
        
        for(int i=0; i<5; i++){
            two_mode[i].mode = 1;
            two_mode[i].directory_num = dir_num[i];
            ret2 = pthread_create(&re_read[i], &attr, scan_dir, (void *)&two_mode[i]);
            
        }
        
        pthread_join(re_read[0], NULL);
        pthread_join(re_read[1], NULL);
        pthread_join(re_read[2], NULL);
        pthread_join(re_read[3], NULL);
        pthread_join(re_read[4], NULL);
        
    }
    
    else if(flag ==2){ // verify mode
        
        for(i=0; i<5; i++){
            two_mode[i].mode = 2;
            two_mode[i].directory_num = dir_num[i];
            ret = pthread_create(&dir[i], &attr, scan_dir, (void *)&two_mode[i]); // i: directory num
            
        }
        
        pthread_join(dir[0], NULL);
        pthread_join(dir[1], NULL);
        pthread_join(dir[2], NULL);
        pthread_join(dir[3], NULL);
        pthread_join(dir[4], NULL);
    }
    
}

/* unset the file attributes */
void ocall_delete_file(const char *name, char attr, int dir)
{
    int io_ret, fd, f_attr;
    char name_buffer[140];
    char system_buffer[160];
    uint32_t ex_flag = 0x00080000;
    
    memset(name_buffer, 0, 140);
    memset(system_buffer, 0, 160);
    
    if(attr == 'a'){
        
        sprintf(name_buffer, "/home/lass/worm_files/%d/append/%s", dir, name);
        
    }
    
    else if(attr == 'i'){
        
        sprintf(name_buffer, "/home/lass/worm_files/%d/immutable/%s", dir, name);
        
    }
    
    LOG_V("len: [%ld], string: %s\n", strlen(name), name);
    LOG_V("file to delete: %s\n", name_buffer);
    
    fd = open(name_buffer, O_RDONLY);
    
    if(fd<0)
        printf("open error: %d \n", errno);
    
    // first, get file attribute
    io_ret = ioctl(fd, FS_IOC_GETFLAGS, &f_attr);
    
    if(io_ret<0)
        printf("get flags error: %d \n", errno);
    
    f_attr &= 0x0;
    f_attr |= ex_flag;
    
    // set file attribute to extent
    io_ret = ioctl(fd, FS_IOC_SETFLAGS, &f_attr);
    
    if(io_ret<0)
        printf("set flags error: %d \n", errno);
    
    close(fd);
    
    // delete that file automatically
    sprintf(system_buffer, "rm %s", name_buffer);
    
    // rm file
    system(system_buffer);
}


void ocall_set_file(char *name, char attr, int retention, int dir)
{
    const char *success_pipe = "/tmp/success";
    char name_buffer[130];
    char success_msg[140];
    char attr_buffer[16]={0};
    char get_ret[16] = {0};
    int fd, ret, flag, f_attr, io_ret, pipe_fd, fcntl_flags;
    bool suc_flag = true;
    
    pipe_fd = open(success_pipe, O_WRONLY | O_NONBLOCK);
    //	fcntl_flags = fcntl(pipe_fd, F_GETFL, 0);
    //	fcntl_flags |= O_NONBLOCK;
    //	fcntl(pipe_fd, F_SETFL, fcntl_flags);
    memset(name_buffer, 0, 130);
    memset(success_msg, 0, 140);
    if(attr == 'a'){
        sprintf(name_buffer, "/home/lass/worm_files/%d/append/%s", dir, name);
        flag = 0x20;
    }
    
    if(attr == 'i'){
        sprintf(name_buffer, "/home/lass/worm_files/%d/immutable/%s", dir, name);
        flag = 0x10;
    }
    
    LOG_V("len: [%ld], string: %s\n", strlen(name), name);
    
    // directory path saved in name_buffer
    sprintf(attr_buffer, "%d", retention);
    
    ret = setxattr(name_buffer, "trusted.retention", attr_buffer, strlen(attr_buffer)+1, 0);
    if(ret<0)
        printf("%s: \n", strerror(errno));
    
    ret = getxattr(name_buffer, "trusted.retention", get_ret, strlen(attr_buffer)+1);
    
    if(ret<0){
        printf("%s: \n", strerror(errno));
        suc_flag = false;
    }
    
    else if(!(ret<0))
        LOG_V("retention value %s successfully saved to file %s\n", get_ret, name);
    
    //while( fd = open(name_buffer, O_RDWR | O_SYNC) != -1);
    
    /*
     while(1){
     fd = open(name_buffer, O_RDWR | O_SYNC);
     if(fd != -1)
     break;
     }
     */
    fd = open(name_buffer, O_RDWR | O_SYNC);
    if(fd<0)
        printf("open error %s: \n", strerror(errno));
    
    io_ret = ioctl(fd, FS_IOC_GETFLAGS, &f_attr);
    
    if(io_ret != 0)
        printf("get flags error %s: \n", strerror(errno));
    
    LOG_V("attr is %x\n", f_attr);
    // f_attr &= 0x0;
    f_attr |= flag;
    io_ret = ioctl(fd, FS_IOC_SETFLAGS, &f_attr);
    
    if(io_ret != 0){
        suc_flag = false;
        printf("set flags error %s: \n", strerror(errno));
    }
    
    if(suc_flag == true){
        sprintf(success_msg, "%s SUCCESS", name_buffer);
    }
    
    else if(suc_flag == false){
        sprintf(success_msg, "%s FAIL", name_buffer);
    }
    
    write(pipe_fd, success_msg, strlen(success_msg));
    LOG_V("wrote to WORM_messages pipe!\n");
    
    memset(name_buffer, 0, 130);
    memset(success_msg, 0, 140);
    
    close(pipe_fd);
    close(fd);
}

/* file info receiving thread from inotify shell */

void *file_receiver(void *num)
{
    real *get_file; // struct real to save file name, attribute, retention
    const char *pipe ="/tmp/worm_file_info"; // pipe for receiving newly arrived file info
    
    // etc variables for parsing file path
    char tmp[128];
    char tmp_compare[128]={0};
    char convey[30];
    char *tok;
    
    int len;
    int flag=0;
    int ret;
    int fd;
    int fcntl_flags;
    int mode;
    int meaningless=0;
    
    FILE *fp;
    
    memset(convey, 0, 30);
    
    printf("file receiver thread running!\n");
    
    // open pipe
    fp = fopen(pipe, "r");
    
    fd = fileno(fp);
    fcntl_flags = fcntl(fd, F_GETFL, 0);
    fcntl_flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, fcntl_flags);
    
    if(fp<0)
        perror("pipe open error\n");
    
    while(1){
        
        fgets(tmp, 100, fp);
        
        // prevent from reading same file information again
        // Sometimes, same file info remains in the pipe
        if(!strcmp(tmp, tmp_compare)){
            
        }
        
        else{
            // get trusted time before saving file attributes
            get_time();
            
            get_file = (real*)malloc(sizeof(real));
            
            // parse file path string (delimiter: /)
            // path format is like, 3/append/test1.txt
            tok = strtok(tmp, "/");
            
            while(tok != NULL)
            {
                
                strcpy(convey, tok);
		printf("string: %s\n", convey);                
                // First, get file retention
                if(flag == 0){
                    
                    get_file->directory = atoi(convey);
                    
                }
                
                // Second, get file attribute
                else if(flag == 1){
                    
                    // append => a
                    if(!strcmp(convey, "append")){
                        get_file->attr = 'a';
                    }
                    
                    // immutable => i
                    else if(!strcmp(convey, "immutable")){
                        get_file->attr = 'i';
                    }
                    else{
                        printf("file attribute error! Tell admin\n");
                    }
                }
                
                // Third, get file name
                else if(flag == 2){
                    // set file name
                    strcpy(get_file->name, convey);
                    len = strlen(get_file->name);
                    get_file->name[len-1] = '\0';
                }
                
                tok = strtok(NULL, "/");
                
                flag++; // flag is for parsing file retention, file attribute, and file name
                memset(convey, 0, 30);
            }
            
            flag = 0;
            
            // save file metadata into enclave
            
            mode = 2; // mode != 1 is saving new file into enclave(received file info from "tester" pipe)
            
            // save file name, attribute, directory(retention) into Enclave
            ecall_status = save_file_info(global_eid, &ret, get_file->name, &(get_file->attr), &(get_file->directory),
                                          &meaningless, &mode);
            //jinhoon
            //여기에 pass by reference로 암호화된거 추가하자
            //근데 이러면 입력할때 취약함
            //사실 근데 기존에도 입력할때 취약했음.
            
            //+ 수정 pass_string 함수로 빼기로 결심
            
            //+ 수정 pass_string 에서 아예 push_back 또한 해줌
            
            if(ret==1)
                LOG_V("Save complete\n");
            
            memset(tmp, 0, 256);
            free(get_file);
            LOG_V("one loop\n");
        }
        
        strcpy(tmp_compare, tmp);
        
    }
    
    fclose(fp);
}

void *get_timeserver(void *t)
{
    char ip_addr[20]; // get timeServer ip addr from Enclave
    char port_n[20]; // get timeServer port num from Enclave
    
    // variables for receiving time from timeServer
    unsigned char recv_time[16]; // time format example: 202075/235800 (maximum strlen is 13)
    unsigned char md[33]; // received MAC value goes here
    int ret, n, sockfd, port; // etc for socket
    int iMode = 0;
    struct sockaddr_in servaddr;
    
    // get ip addr and port number info from Enclave
    ecall_status = get_socket(global_eid, (void *)ip_addr, (void *)port_n);
    
    LOG_V(SEPARATOR);
    LOG_V("\n");
    LOG_V("Getting time from external time server..\n");
    
    if(ecall_status != SGX_SUCCESS){
        printf("ecall error on get_time_server!\n");
    }
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if(sockfd == -1){
        perror("Unable to create socket for time server!\n");
    }
    
    // null buffering
    ioctl(sockfd, _IONBF, &iMode);
    memset(&servaddr, 0, sizeof(servaddr));
    
    port = atoi(port_n);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip_addr);
    servaddr.sin_port = htons(port);
    
    // initialize arrays for socket read
    memset(recv_time, 0, 16);
    memset(md, 0, 33);
    
    ret = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    
    if(ret<0){
        printf("Socket connection failed!!!\n");
    }
    // get time & corresponding HMAC value
    n = read(sockfd, recv_time, 16);
    n = read(sockfd, md, 33);
    
    LOG_V("received time is %s, len is [%d]\n", recv_time, strlen((const char *)recv_time));
    LOG_V("received MAC is %s, len is [%d]\n", md, strlen((const char *)md));
    
    // calculate MAC value inside Enclave
    ecall_status = compare_mac_and_save(global_eid, &ret, recv_time, md);
    
    if(ecall_status != SGX_SUCCESS){
        printf("ecall error!\n");
    }
    
    if(ret == -1){
        printf("MAC code mismatch!!! alert admin\n");
    }
    
    else if(ret != -1){
        printf("MAC code authenticated\n");
    }
    
    close(sockfd);
    
    pthread_exit((void *)t);
}


/* get local time & trusted time */
void get_time()
{
    int time_local; // WORM server local time
    int suc, rc; // ECALL and pthread_create ret val
    
    // time related structure
    time_t rawtime;
    struct tm *t_info;
    char real_month[3];
    char real_day[3];
    
    time(&rawtime);
    t_info = localtime(&rawtime);
    
    memset(real_month, 0, 3);
    memset(real_day, 0, 3);
    //init
    
    if(t_info->tm_mon < 9)
        sprintf(real_month, "0%d", t_info->tm_mon+1);
    
    else if(t_info->tm_mon >=10)
        sprintf(real_month, "%d", t_info->tm_mon+1);
    
    if(t_info->tm_mday < 10)
        sprintf(real_day, "0%d", t_info->tm_mday);
    
    else if(t_info->tm_mday >=10)
        sprintf(real_day, "%d", t_info->tm_mday);
    
    sprintf(time_info, "%d%s%s", 1900 + t_info->tm_year, real_month, real_day);
    
    time_local = atoi(time_info);
    
    // first, save local time in enclave
    ecall_status = save_local_time(global_eid, time_local);
    
    // create thread for time_server
    rc = pthread_create(&comp_clock, NULL, get_timeserver, (void *)0);
    
    if(rc){
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        exit(-1);
    }
    
    // wait until get_timeserver thread is done
    pthread_join(comp_clock, NULL);
    
    LOG_V(SEPARATOR);
    LOG_V("\n");
    LOG_V("Comparing local time and time server time..\n");
    LOG_V("\n");
    
    // compare WORM local time and Time Server time.. suc: return value from ECALL
    ecall_status = compare_enclave_time(global_eid, &suc);
    
    if(ecall_status != SGX_SUCCESS)
        printf("ecall error on co\n");
    
    if(suc == 1)
        printf("Correct time authenticated!\n");
    
    if(suc == -1)
        printf("time mismatch! following timeServer time..\n");
    
    
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    
    int suc;
    int rc;
    
    int fd3;
    char test_result[101];
    
    printf(SEPARATOR);
    printf("\n");
    printf("SGX WORM Storage Demo\n");
    
    
    // Initialize the enclave
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    //jinhoon
    //resize vectors
    for(int i = 0 ; i < 5; i++){
        secure_file[0].resize(100);
    }
    
    /*
    //for debug
    char _name[] = "hello";
    char _attr = 0;
    int _dir = 1;
    int _retention = 10;
    int _mode = 1;
    int ret = 0;
    save_file_info(global_eid, &ret, _name, &_attr, &_dir, &_retention, &_mode);
    checker(global_eid, &ret, secure_file[0][ret_hash_value][0]);
     */
    
    //마지막 파라미터 벡터로 표현해서 해보기
    //debug end
    // get time for the first time
    get_time();
    
    // If "RECAP" is given as an 1st argument, re-read worm_files metadata info (attr & retention time)
    if(argv[1]){
        
        if(strcmp(argv[1], "RECAP") == 0){
            
            verify_file(1);
            
        }
    }
    
    // going to make file_receiver thread as detached
    pthread_attr_init(&attr);
    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    if(rc)
        printf("During attr_setdetachstate.. invalid value was specified!\n");
    
    // run 4 file_receiver thread
    printf("preapring for file_receiver thread\n");
    //for(int i = 0; i < 4; i++){
    //ret_encrypted_data = (unsigned char*)malloc(ENC_SIZE);
    //jinhoon
    //size of encrypted content
    // 64 + 1 + 4 + 4 = 73 (struct file_info of enclave)
    // + 560
    
    rc = pthread_create(&file_receive, &attr, file_receiver, NULL);
    
    if(rc){
        printf("ERROR; return code from file_receiver is %d\n", rc);
        exit(-1);
        
    }
    // }
    
    // main thread will go to sleep and wait for verify & delete routine
    while(1){
        
        // will be used for calculating sleep time
        int hour, min, sec;
        int hour_left, min_left, sec_left;
        int time_to_sleep;
        
        // hour, min, sec value from ECALL will be saved here
        char hh[3];
        char mm[3];
        char ss[3];
        
        LOG_V("getting hour, min, sec from enclave\n");
        
        // get hour, min, sec to calculate sleep time
        ecall_status = get_hms(global_eid, (void *)hh, (void *)mm, (void *)ss); // get hour, min, sec from enclave (previously saved)
        
        LOG_V("hour is %s\n", hh);
        LOG_V("min is %s\n", mm);
        LOG_V("sec is %s\n", ss);
        
        hour = atoi(hh);
        min = atoi(mm);
        sec = atoi(ss);
        
        // calculate sleep time. Base time is 01:00 AM
        if(hour == 0)
            hour_left = 0;
        
        else
        {
            hour_left = 23 - hour;
        }
        
        min_left = 59 - min;
        sec_left = 60 - sec;
        
        time_to_sleep = (hour_left * 3600) + (min_left * 60) + sec_left;
        
        LOG_V("%d secs before launching verify & delete routine..\n", time_to_sleep);
        
        // sleep
        sleep(time_to_sleep);
        
        // Run verify routine
        get_time(); // before verify routine, get trusted time from timeServer
        
        verify_start = clock();
        
        verify_file(2);
        
        verify_end = clock();
        
        verify_cpu_time = ((double) (verify_end - verify_start)) / CLOCKS_PER_SEC;
        
        LOG_V("Verifying Files took %f sec!!!\n", verify_cpu_time);
        
        
        get_time(); // // before delete routine, get trusted time from timeServer
        
        delete_start = clock();
        
        //jinhoon
        //if retention time exceeded, remove file
        for(int i = 0; i < 5; i++){
            for(int j = 0; j < secure_file[i].size(); j++){
                for(int u = 0; u < secure_file[i][j].size(); u++){
                    ecall_status = checker(global_eid, &suc, secure_file[i][j][u]);
                    if(suc == -1){
                        secure_file[i][j].erase(secure_file[i][j].begin()+u);
                    }
                }
            }
        }
        //ecall_status = checker(global_eid, &suc);
        
        delete_end = clock();
        
        printf("Deleting sequence Ended!!!!!!!!!!!!!!!!!!\n");
        
        delete_cpu_time = ((double) (delete_end - delete_start)) / CLOCKS_PER_SEC;
        
        LOG_V("Deleting Files took %f sec!!!\n", delete_cpu_time);
        
        fd3 = open("result.txt", O_RDWR | O_CREAT, 0666); // save exec time into a file
        
        memset(test_result, 0, 101);
        
        sprintf(test_result, "verify took %f sec, delete took %f sec\n", verify_cpu_time, delete_cpu_time);
        
        write(fd3, test_result, 101);
        
        close(fd3);
    }
    
    sgx_destroy_enclave(global_eid);
    printf("enclave destroyed!\n");
    printf("\n");
    printf(SEPARATOR);
    
    return 0;
}
