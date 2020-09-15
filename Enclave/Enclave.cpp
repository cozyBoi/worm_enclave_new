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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "sgx_trts.h"
#include "sgx_tseal.h"

using namespace std;

#define file_info_size 73
#define sealed_size (560 + file_info_size)

int time_local; // WORM Server local time is saved here
int time_server; // Time Server is saved here
int hour, min, sec, left; // tmp variable for time

//vector<file_info> secure_file[5]; // all file inforamtion is saved in this vector ([0]: directory 0, [1]: directory 1, [2]: directory 3...)

unsigned char hh[3]; // hour
unsigned char mm[3]; // min
unsigned char ss[3]; // sec

char hmac_msg[] = "soteria";
int hmac_len = 7;

const unsigned char *p_key = (const unsigned char *)"This is a key!! Yes!! :)"; // Key for generating HMAC
const char *ip_addr = "127.0.0.1"; // time server ip addr
const char *port_num = "7998"; // temporarily opened port 7998

char save_year[5]; // tmp variable for time
char save_month[5]; // tmp variable for time

// used for sort
bool cmp(const file_info &a, const file_info &b)
{
    if(a.retention < b.retention) return true;
    
    return false;
}

// compare Worm Server time and Time Server Time
int compare_enclave_time()
{
    
    if(time_local == time_server){ // If time(year, month, day) matches.. OK
        
        return 1;
    }
    
    else // time mismatch
    {
        time_local = time_server;
        return -1;
    }
    
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

// copy hour, min, sec from enclave to untursted area (This is for setting routine sleep time)
void get_hms(void *h, void *m, void *s)
{
    
    memcpy(h, hh, strlen((const char *)hh)+1);
    memcpy(m, mm, strlen((const char *)mm)+1);
    memcpy(s, ss, strlen((const char *)ss)+1);
    
}

// Give ip addr and port num
void get_socket(void *str1, void *str2)
{
    memcpy(str1, ip_addr, strlen(ip_addr)+1);
    memcpy(str2, port_num, strlen(port_num)+1);
}

// Save file info in vector<file_info>
int save_file_info(const char *name, const char *attr, const int * dir, const int *retention, const int *mode)
{
    file_info tmp;
    int dir_index= *dir;
    int timeserver_tmp;
    int month_len;
    
    // copy data sent through ECALL
    strlcpy(tmp.name, name, sizeof(tmp.name));
    
    tmp.attr = *attr;
    tmp.dir = *dir;
    
    // first time receiving file and saving.. (called from file_receiver)
    if(*mode != 1){
        
        timeserver_tmp = atoi(save_year);
        
        timeserver_tmp += (*dir); // add year
        
        month_len = strlen(save_month);
        
        // 2: * 100, 3: * 1000, 4: * 10000 (manipulating tens digit)
        if(month_len == 2)
            tmp.retention = (timeserver_tmp * 100) + atoi(save_month);
        
        else if(month_len == 3)
            tmp.retention = (timeserver_tmp * 1000) + atoi(save_month);
        
        else if(month_len == 4)
            tmp.retention = (timeserver_tmp * 10000) + atoi(save_month);
        
    }
    
    // called from re_meta (by ./app RECAP)
    //mode == 1 이면 그냥 넣기, 0이면 계산해서 넣기
    else if(*mode == 1){
        tmp.retention = *retention;
    }
    
    // adjust vector index to directory number
    if(dir_index == 1)
        dir_index = 0;
    else if(dir_index==3)
        dir_index = 1;
    else if(dir_index==5)
        dir_index = 2;
    else if(dir_index==7)
        dir_index = 3;
    else if(dir_index==10)
        dir_index = 4;
    
    // save file info into vector
    //secure_file[dir_index].push_back(tmp);
    
    // sort by retention time
    //sort(secure_file[dir_index].begin(), secure_file[dir_index].end(), cmp);
    
    // If this is first time saving file information, call OCALL and save it into file metadata
    if(*mode != 1)
        ocall_set_file(tmp.name, tmp.attr, tmp.retention, tmp.dir);
    
    //jinhoon
    //여기에 마샬링하고 암호화하자
    unsigned char marshalled_data[file_info_size];
    unsigned char sealed_data[sealed_size];
    
    memcpy(marshalled_data, name, 64);
    memcpy(marshalled_data + 64, attr, 1);
    memcpy(marshalled_data + 64 + 1, dir, 4);
    memcpy(marshalled_data + 64 + 1 + 4, retention, 4);
    //marshalling
    
    ocall_print_hex(marshalled_data, file_info_size);
    
    uint32_t plaintext_len = file_info_size;
    sgx_seal_data((uint32_t)hmac_len, (uint8_t*)hmac_msg, plaintext_len, (uint8_t*)marshalled_data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    //sealing
    int len = strlen(name);
    int hash_value = 0;
    for(int i = 0; i < len; i++){
        hash_value += name[i];
    }
    
    ocall_pass_string(sealed_data, hash_value % 100, dir_index); //, hash value 도 보내자
    //passing
    
    return 1;
    
}

// got local time
void save_local_time(int time)
{
    time_local = time;
    
}


// Check if there is any file to delete
int checker(unsigned char*sealed_data)
{
    //jinhoon
    char plaintext[file_info_size];
    uint32_t plaintext_len = file_info_size;
    sgx_unseal_data((sgx_sealed_data_t*)sealed_data, (uint8_t*)hmac_msg, (uint32_t*)&hmac_len, (uint8_t*)plaintext, &plaintext_len);
    
    unsigned char debug_txt[file_info_size];
    memcpy(debug_txt, plaintext, file_info_size);
    ocall_print_hex(debug_txt, file_info_size);
    
    char _name[64];
    char _attr;
    int _dir;
    int _retention;
    
    memcpy(_name, plaintext, 64);
    memcpy(&_attr, &plaintext[64], 1);
    memcpy(&_dir, &plaintext[65], 4);
    memcpy(&_retention, &plaintext[69], 4);
    
    if(_retention > time_server)
        return 0;
    
    // file to delete
    else{
        //jinhoon
        //vector의 내용물은 checker를 부르는 부분에서 지움
        ocall_delete_file(_name, _attr, _dir);
        return -1;
    }
    
    /*
    vector<file_info>::iterator it;
    
    for(int i = 0; i<5; i++){
        for(it = secure_file[i].begin(); it != secure_file[i].end(); it++){
            
            // no file to delete
            if(it->retention > time_server)
                break;
            
            // file to delete
            else{
                ocall_delete_file(it->name, it->attr, it->dir);
                it = secure_file[i].erase(it); // erase vector element
                it--;
            }
            
        }
    }
    */
    return 1;
}


// Verify file metadata saved in disk
int verifier(const char *name, const char *attr, const int *retention,  const int * dir, unsigned char*sealed_data)
{
    //jinhoon
    int dir_index = *dir;
    char f_attr = *attr;
    int ret = *retention;
    
    char plaintext[file_info_size];
    uint32_t plaintext_len = file_info_size;
    sgx_unseal_data((sgx_sealed_data_t*)sealed_data, (uint8_t*)hmac_msg, (uint32_t*)&hmac_len, (uint8_t*)plaintext, &plaintext_len);
    
    unsigned char debug_txt[file_info_size];
    memcpy(debug_txt, plaintext, file_info_size);
    ocall_print_hex(debug_txt, file_info_size);
    
    char _name[64];
    char _attr;
    int _dir;
    int _retention;
    
    memcpy(_name, plaintext, 64);
    memcpy(&_attr, &plaintext[64], 1);
    memcpy(&_dir, &plaintext[65], 4);
    memcpy(&_retention, &plaintext[69], 4);
    
    if(!strcmp(name, _name)){
        
        if(f_attr == _attr){
            
            if(ret == _retention){
                
                
            }
            
            else{
                return -1;
            }
            
        }
        
        else{
            return -1;
        }
        // no problem
        return 1;
    }
    
    /*
    vector<file_info>::iterator it;
    int dir_index = *dir;
    char f_attr = *attr;
    int ret = *retention;
    */
    
    /*
    if(dir_index == 1)
        dir_index = 0;
    if(dir_index==3)
        dir_index = 1;
    else if(dir_index==5)
        dir_index = 2;
    else if(dir_index==7)
        dir_index = 3;
    else if(dir_index==10)
        dir_index = 4;
    */
    
    /*
    for(it = secure_file[dir_index].begin(); it != secure_file[dir_index].end(); it++){
        
        if(!strcmp(name, it->name)){
            
            if(f_attr == it->attr){
                
                if(ret == it->retention){
                    
                    
                }
                
                else{
                    return -1;
                }
                
            }
            
            else{
                return -1;
            }
            // no problem
            return 1;
        }
    }
    */
    return 0;
}   



/* 1st parameter: original message, 2nd parameter: MAC retrieved from Time Server
 Not used right now. Left it for future use */
int compare_mac(const unsigned char *msg, const unsigned char *recv_MAC)
{
    sgx_status_t ret;
    unsigned char p_mac[33] = {'\0'};
    int mac_len;
    
    mac_len = strlen((const char *)recv_MAC);
    
    /* use hmac_sha256 function provided from SGX, included in sgx_tcrypto.h */
    ret = sgx_hmac_sha256_msg(msg, strlen((const char *)msg), p_key, strlen((const char *)p_key),
                              p_mac, mac_len);
    
    for(int i=0; i<mac_len; i++)
    {
        if(p_mac[i] != recv_MAC[i])
        {
            return -1;
        }
    }
    
    return 1;
}



/* 1st parameter: original message, 2nd parameter: MAC retrieved from Time Server */
int compare_mac_and_save(const unsigned char *msg, const unsigned char *recv_MAC)
{
    sgx_status_t ret;
    unsigned char p_mac[33] = {'\0'};
    int mac_len;
    char * time_split;
    
    mac_len = strlen((const char *)recv_MAC);
    
    /* use hmac_sha256 function provided from SGX, included in sgx_tcrypto.h */
    ret = sgx_hmac_sha256_msg(msg, strlen((const char *)msg), p_key, strlen((const char *)p_key),
                              p_mac, mac_len);
    
    for(int i=0; i<mac_len; i++)
    {
        if(p_mac[i] != recv_MAC[i])
        {
            return -1;
        }
    }
    // initialize hour, min, sec array
    memset(hh, 0, 3);
    memset(mm, 0, 3);
    memset(ss, 0, 3);
    
    time_split = strtok((char *)msg, "/"); // received time format is like (yyyymmdd/hhmmss)
    
    time_server = atoi((const char *)time_split); // First, get year, month, day and save it as integer
    
    strncpy(save_year, time_split, 4);
    
    strncpy(save_month, time_split+4, strlen(time_split)-4);
    
    time_split = strtok(NULL, "/"); // Second, get hour, min, sec
    
    memcpy(hh, time_split, 2);
    
    memcpy(mm, time_split + 2, 2);
    
    memcpy(ss, time_split + 4, 2);
    
    return 1;
}
