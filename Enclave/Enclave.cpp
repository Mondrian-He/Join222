/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#include "Enclave_t.h" /* print_string */
#include "baddtree.h"
#include "data_ebuffer.h"
#include "encode.h"
#include "kdtree.h"
#include "BloomFilter.h"
#include "BIGSI.h"
#include "CSCBF.h"
#include "Ocall_wrappers.h"
#include "ObliviousSort.h"

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
#include <time.h>

#include <functional>
#include <memory>
#include <unordered_map>

using namespace BAT;

string cbc_key1 = "12345678901234561234567890123456";
string cbc_key2 = "98765432101234569876543210123456";
string iv0 = "1000000000000000";
string iv1 = "1111111111111111";
string iv2 = "2000000000000000";
string iv3 = "2111111111111111";
string iv4 = "3000000000000000";
string iv5 = "3111111111111111";
string iv6 = "4000000000000000";
string iv7 = "4111111111111111";
string iv8 = "5000000000000000";
string iv9 = "5111111111111111";
long long liv1 = atoll(iv0.c_str());

// #define NUM_DB 10
#define HASH_NUM 3
#define REP_TIME 3
#define PART_NUM 62
#define TOTAL_CAP 60000

BAddTree<int,k_r>* tree;

void ecall_init(int order)
{
    printf("ecall_init\n");
    for(int i=1;i<=EBUFFER_SIZE;i++)
    {
        MBuf_id mbuf_id;
        mbuf_id.page_id = (i-1)/4 + 1;
        mbuf_id.offset = (i-1)%4;
        node2page[i] = mbuf_id;
    }
    for(int i = 0; i < 16; i++)
    {
        key[i] = 32 + i;
    }

    tree = new BAddTree<int,k_r>(order);

}

int ecall_search(int key,void* mbdes,char** mbpool)
{
    printf("ecall_search\n");
    return tree->find(key,(MBuf_des*)mbdes,mbpool)->rid;
    
}

void ecall_insert(void* key_rid,void* mbdes,char** mbpool)
{
    printf("ecall_insert\n");
    k_r* kr = (k_r*)key_rid;
    tree->insert(*kr,(MBuf_des*)mbdes,mbpool);
    
}

auto itf = [&](deque <k_r*>&e) {
	int _s = e.size();
	for (int i = 0; i < _s; ++i) {
		printf("%d ", e[i]->k);
	}
};

void ecall_traversal()
{
    printf("ebuffer size: %d\n",tree->ebuffer->size);
    printf("tree size: %d\n",tree->size());
    printf("start traversal:\n");
    tree->list_traversal(itf);
}

Data_EBuffer *Def;

void ecall_data_init()
{
    printf("ecall_data_init\n");

    for(int i = 0; i < 16; i++)
    {
        key2[i] = 32 + i;
    }

    Def = new Data_EBuffer(-1);
}
char* ecall_data_search(int rid,void* mbdes,char** mbpool)
{
    printf("ecall_data_search\n");
    return Def->SearchData(rid,(MBuf_des*)mbdes,mbpool);
    
}

void ecall_data_insert(char* newdata,void* mbdes,char** mbpool)
{
    printf("ecall_data_insert\n");
    Def->InsertData(newdata,(MBuf_des*)mbdes,mbpool);
    
}

// unsigned int hashFunction(string word, unsigned int hashNum) {
//     unsigned int hashValue = 5381;
//     for (char c : word) {
//         hashValue = ((hashValue << 5) + hashValue) + c; // djb2 hash function
//     }
//     hashValue *= hashNum;
//     return hashValue;
// }

// // Oblivious Bloom Filter Membership Test
// bool OBFMT(string query, CSCBF& cscbf) {
//     int m = TOTAL_CAP/REP_TIME;
//     vector<int> hashesQ(HASH_NUM);
//     vector<int> testVector(m,0);

//     for (int i = 0; i < HASH_NUM; i++) {
//         hashesQ[i] = hashFunction(query, i) % m;
//     }

//     for (int i : hashesQ) {
//         for (int j = 0; j < m; j++) {
//             if(i == j) testVector[j] = 1;
//             else testVector[j] = 0;
//         }
//     }

//     int result = 1;
//     for (int i = 1; i < m; i++) {
//         int cscbf_res = cscbf.query(i, query);
//         testVector[i] &= cscbf_res;
//         result += testVector[i];
//     }

//     result -= HASH_NUM;

//     if (result == 0) {
//         return true;
//     } else {
//         return false;
//     }
// }

void ecall_joinsearch1(char** ein1,char** ein2,void* mbdes,char** mbpool)
{ 

    clock_t s2,e2;
    s2 = sgx_clock();

    ocall_open_result();
    ocall_open_enquery();

    char *enumber = new char[25];
    ocall_read_s(enumber,25);
    string senumber = enumber;
    string number_decode_base64 = base64_decode(senumber);
	string sn = aes_256_cbc_decode(cbc_key1,iv1,number_decode_base64);
    int num = atoi(sn.c_str());
    printf("num:%d \n",num);
    liv1++;

    vector<int> table;
    for(int i=0;i<num;i++){
        char *en = new char[25];
        ocall_read_s(en,25);
        string sen = en;
        string niv1 = to_string(liv1);
        liv1++;
        string n_decode_base64 = base64_decode(sen);
	    string n = aes_256_cbc_decode(cbc_key1,niv1,n_decode_base64);
        table.push_back(atoi(n.c_str()));
    }

    int len1 = 0;
    vector<string> index1;
    ocall_read_eneq1(&len1,ein1);
    
    int len2 = 0;
    vector<string> index2;
    ocall_read_eneq2(&len2,ein2);

    BIGSI baseline_bigsi(num, HASH_NUM, TOTAL_CAP);
    vector< pair<int,int> > storage2;
    map<string,int> result1;
    map<string,int> result2;

    for(int p1=0;p1<len1;p1++)
    {
        string enindex1 = ein1[p1];
        string p1_decode_base64 = base64_decode(enindex1);
	    string p1_decode = aes_256_cbc_decode(cbc_key2,iv1, p1_decode_base64);
        index1.push_back(p1_decode);//是一个string的vector
        baseline_bigsi.insertion(0,p1_decode);
    }

    for(int p2=0;p2<len2;p2++)
    {
        string enindex2 = ein2[p2];
        string p2_decode_base64 = base64_decode(enindex2);
	    string p2_decode = aes_256_cbc_decode(cbc_key2,iv2, p2_decode_base64);
        index2.push_back(p2_decode);	    
	    baseline_bigsi.insertion(1,p2_decode);
    }

    std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity,false);
    Cmp_Array = baseline_bigsi.query(0,1);

    for(int i=0;i<index2.size();i++)
    {
            int res = 1;
            vector<size_t> check_locations = BF_Hash(index2[i], baseline_bigsi.k, baseline_bigsi.seed, baseline_bigsi.single_capacity);
            for (auto &location : check_locations)
            {
                res &= Cmp_Array[location];
            }
            if (res)
            {
                result2[index2[i]] = i;
            }

    }
    for(int j=0;j<index1.size();j++)
    {
	    if(result2.find(index1[j]) != result2.end())
            result1[index1[j]] = j;
        
    }

    unordered_map<string,int> HTE;
    for(auto h1 : result1)
    {
        HTE[h1.first] = h1.second;
    }
    for(auto h2 : result2)
    {
        if(HTE.find(h2.first) != HTE.end())
        {
            storage2.push_back(pair<int,int>(HTE[h2.first],h2.second));
            // ocall_write_result(atoi(h2.first.c_str()));
            // ocall_writeendl_result();
        }
    }

    ocall_close_enquery();
    ocall_close_result();

    e2 = sgx_clock();
    printf("\ntra执行时间: %f us\n", (double)((e2 - s2)));
}

// void ecall_joinsearch1(char** ein0,char** ein1,char** ein2,char** ein3,char** ein4,char** ein5,char** ein6,char** ein7,char** ein8,char** ein9,void* mbdes,char** mbpool)
// { 
//     ocall_open_result();
//     ocall_open_enquery();

//     clock_t s2,e2;
//     s2 = sgx_clock();

//     char *enumber = new char[25];
//     ocall_read_s(enumber,25);
//     string senumber = enumber;
//     string number_decode_base64 = base64_decode(senumber);
// 	string sn = aes_256_cbc_decode(cbc_key1,iv0,number_decode_base64);
//     int num = atoi(sn.c_str());
//     printf("num:%d \n",num);
//     liv1++;

//     vector<int> table;
//     for(int i=0;i<num;i++){
//         char *en = new char[25];
//         ocall_read_s(en,25);
//         string sen = en;
//         string niv1 = to_string(liv1);
//         liv1++;
//         string n_decode_base64 = base64_decode(sen);
// 	    string n = aes_256_cbc_decode(cbc_key1,niv1,n_decode_base64);
//         table.push_back(atoi(n.c_str()));
//     }

//     BIGSI baseline_bigsi(num, HASH_NUM, TOTAL_CAP);
//     vector< pair<int,int> > storage2;

//     int len0 = 0;
//     ocall_read_eneq0(&len0,ein0);
//     vector<string> index;
//     map<string,int> result0;    

//     int len1 = 0;
//     ocall_read_eneq1(&len1,ein1);
//     map<string,int> result1;

//     for(int p=0;p<len0;p++)
//     {
//         string enindex = ein0[p];
//         string p_decode_base64 = base64_decode(enindex);
// 	    string p_decode = aes_256_cbc_decode(cbc_key2,iv0,p_decode_base64);
//         index.push_back(p_decode);   
//         printf("index0:%s\n",p_decode);    
//         baseline_bigsi.insertion(0,p_decode);
//     }

//     if(num == 2){
//         for(int p=0;p<len1;p++)
//         {
//             string enindex = ein1[p];
//             string p_decode_base64 = base64_decode(enindex);
//             string p_decode = aes_256_cbc_decode(cbc_key2,iv1, p_decode_base64);
//             printf("index1:%s\n",p_decode);       	    
//             baseline_bigsi.insertion(1,p_decode);

//             // int res = 1;
//             for (int set_ID = 1; set_ID < num; set_ID++)
//             {
//                 std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity,false);
//                 Cmp_Array = baseline_bigsi.query(0,1);

//                 int res = 1;
//                 vector<size_t> check_locations = BF_Hash(p_decode, baseline_bigsi.k, baseline_bigsi.seed, baseline_bigsi.single_capacity);
//                 for (auto &location : check_locations)
//                 {
//                     res &= Cmp_Array[location];
//                 }
//                 if (res)
//                 {
//                     result1[p_decode] = p;
//                 }
                    
//             }
//             // if(res){
//             //     result1[p_decode] = p;
//             // }
//         }
//     }       

//     if(num == 3 || num == 5 || num == 10){
//         int len2 = 0;
//         ocall_read_eneq2(&len2,ein2);
//         for(int p=0;p<len1;p++)
//         {
//             string enindex = ein1[p];
//             string p_decode_base64 = base64_decode(enindex);
//             string p_decode = aes_256_cbc_decode(cbc_key2,iv1, p_decode_base64);
//             printf("index1:%s\n",p_decode);       	    
//             cscbf.insertion(to_string(1),p_decode);
//         }
//         if(num == 3){
//             for(int p=0;p<len2;p++)
//             {
//                 string enindex = ein2[p];
//                 string p_decode_base64 = base64_decode(enindex);
//                 string p_decode = aes_256_cbc_decode(cbc_key2,iv2,p_decode_base64);
//                 printf("index2:%s,",p_decode);       	    
//                 cscbf.insertion(to_string(2),p_decode);

//                 int res = 1;
//                 for (int set_ID = 1; set_ID < num; set_ID++)
//                 {
//                     int cscbf_res = cscbf.query(set_ID,p_decode);
//                     // int cscbf_res = cscbf.obfquery(set_ID,p_decode);
//                     res &= cscbf_res;
//                     if(!res){
//                         break;
//                     }
                        
//                 }
//                 if(res){
//                     result1[p_decode] = p;
//                 }
//             }
//         } else{
//             int len3 = 0;
//             ocall_read_eneq3(&len3,ein3);
//             int len4 = 0;
//             ocall_read_eneq4(&len4,ein4);
//             for(int p=0;p<len2;p++)
//             {
//                 string enindex = ein2[p];
//                 string p_decode_base64 = base64_decode(enindex);
//                 string p_decode = aes_256_cbc_decode(cbc_key2,iv2,p_decode_base64);
//                 printf("index2:%s,",p_decode);       	    
//                 cscbf.insertion(to_string(2),p_decode);
//             }
//             for(int p=0;p<len3;p++)
//             {
//                 string enindex = ein3[p];
//                 string p_decode_base64 = base64_decode(enindex);
//                 string p_decode = aes_256_cbc_decode(cbc_key2,iv3,p_decode_base64);
//                 printf("index3:%s,",p_decode);       	    
//                 cscbf.insertion(to_string(3),p_decode);
//             }            
//             if(num == 5){
//                 for(int p=0;p<len4;p++)
//                 {
//                     string enindex = ein4[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv4,p_decode_base64);
//                     printf("index4:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(4),p_decode);

//                     int res = 1;
//                     for (int set_ID = 1; set_ID < num; set_ID++)
//                     {
//                         int cscbf_res = cscbf.query(set_ID,p_decode);
//                         // int cscbf_res = cscbf.obfquery(set_ID,p_decode);
//                         res &= cscbf_res;
//                         if(!res){
//                             break;
//                         }
                            
//                     }
//                     if(res){
//                         result1[p_decode] = p;
//                     }
//                 }
//             } else{
//                 int len5 = 0;
//                 ocall_read_eneq5(&len5,ein5);
//                 int len6 = 0;
//                 ocall_read_eneq6(&len6,ein6);
//                 int len7 = 0;
//                 ocall_read_eneq7(&len7,ein7);
//                 int len8 = 0;
//                 ocall_read_eneq8(&len8,ein8);
//                 int len9 = 0;
//                 ocall_read_eneq9(&len9,ein9);
//                 for(int p=0;p<len4;p++)
//                 {
//                     string enindex = ein4[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv4,p_decode_base64);
//                     printf("index4:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(4),p_decode);
//                 }                
//                 for(int p=0;p<len5;p++)
//                 {
//                     string enindex = ein5[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv5,p_decode_base64);
//                     printf("index5:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(5),p_decode);
//                 }
//                 for(int p=0;p<len6;p++)
//                 {
//                     string enindex = ein6[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv6,p_decode_base64);
//                     printf("index6:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(6),p_decode);
//                 }
//                 for(int p=0;p<len7;p++)
//                 {
//                     string enindex = ein7[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv7,p_decode_base64);
//                     printf("index7:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(7),p_decode);
//                 }
//                 for(int p=0;p<len8;p++)
//                 {
//                     string enindex = ein8[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv8,p_decode_base64);
//                     printf("index8:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(8),p_decode);
//                 }
//                 for(int p=0;p<len9;p++)
//                 {
//                     string enindex = ein9[p];
//                     string p_decode_base64 = base64_decode(enindex);
//                     string p_decode = aes_256_cbc_decode(cbc_key2,iv9,p_decode_base64);
//                     printf("index9:%s,",p_decode);       	    
//                     cscbf.insertion(to_string(9),p_decode);

//                     int res = 1;
//                     for (int set_ID = 1; set_ID < num; set_ID++)
//                     {
//                         int cscbf_res = cscbf.query(set_ID,p_decode);
//                         // int cscbf_res = cscbf.obfquery(set_ID,p_decode);
//                         res &= cscbf_res;
//                         if(!res){
//                             break;
//                         }
                            
//                     }
//                     if(res){
//                         result1[p_decode] = p;
//                     }
//                 }
//             }
//         }
//     }

//     for(int j=0;j<index.size();j++)
//     {
// 	    if(result1.find(index[j]) != result1.end())
//             result0[index[j]] = j;
        
//     }

//     unordered_map<string,int> HTE;
//     for(auto h1 : result0)
//     {
//         HTE[h1.first] = h1.second;
//     }
//     for(auto h2 : result1)
//     {
//         if(HTE.find(h2.first) != HTE.end())
//         {
//             storage2.push_back(pair<int,int>(HTE[h2.first],h2.second));
//             // ocall_write_result(atoi(h2.first.c_str()));
//             // ocall_writeendl_result();
//         }
//     }

//     e2 = sgx_clock();
//     printf("\ntra执行时间: %f us\n", (double)((e2 - s2)));

//     ocall_close_enquery();
//     ocall_close_result();
// }

void ecall_joinsearch2(char** ein0,char** ein1,char** ein2,char** ein3,char** ein4,char** ein5,char** ein6,char** ein7,char** ein8,char** ein9,void* mbdes,char** mbpool)
{ 
    ocall_open_result();
    ocall_open_enquery();

    clock_t s2,e2;
    s2 = sgx_clock();
    


    char *enumber = new char[25];
    ocall_read_s(enumber,25);
    string senumber = enumber;
    string number_decode_base64 = base64_decode(senumber);
	string sn = aes_256_cbc_decode(cbc_key1,iv0,number_decode_base64);
    int num = atoi(sn.c_str());
    printf("num:%d \n",num);
    liv1++;

    vector<int> table;
    for(int i=0;i<num;i++){
        char *en = new char[25];
        ocall_read_s(en,25);
        string sen = en;
        string niv1 = to_string(liv1);
        liv1++;
        string n_decode_base64 = base64_decode(sen);
	    string n = aes_256_cbc_decode(cbc_key1,niv1,n_decode_base64);
        table.push_back(atoi(n.c_str()));
    }

    CSCBF cscbf(REP_TIME, PART_NUM, TOTAL_CAP, HASH_NUM, num);
    vector< pair<int,int> > storage2;

    int len0 = 0;
    ocall_read_eneq0(&len0,ein0);
    vector<string> index;
    map<string,int> result0;    

    int len1 = 0;
    ocall_read_eneq1(&len1,ein1);
    map<string,int> result1;

    // 设置两个bool类型的vector
    vector<bool> ResultVector_0(len0, false);
    vector<bool> ResultVector_1(len1, false);

    // 分别存储表0和表1的p_decode
    vector<string> p_decode_0(len0);
    vector<string> p_decode_1(len1);

    vector<string> IntersectResult_0;
    vector<string> IntersectResult_1;


    int count;

    


    for(int p=0;p<len0;p++)
    {
        string enindex = ein0[p];
        string p_decode_base64 = base64_decode(enindex);
	    string p_decode = aes_256_cbc_decode(cbc_key2,iv0,p_decode_base64);
        // index.push_back(p_decode);//string vector   
        // 存起来
        p_decode_0[p] = p_decode;
        //打印标签及其p_decode=========================================================================================
        // printf("index0:%s\n",p_decode);    
        cscbf.insertion(to_string(0),p_decode);
    }
     // 打印len0的值
    printf("len0: %d\n", len0);


    // // Print all elements of IntersectResult_0 in a single line
    // printf("p_decode_0 elements: ");
    // for (const auto& elem : p_decode_0) {
    //     printf("%s, ", elem.c_str());
    // }
    // printf("\n");

    if(num == 2){
        int count_test1=0;//测试交集个数
         // 打印len0的值
        printf("len1: %d\n", len0);
        for(int p=0;p<len1;p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2,iv1, p_decode_base64);
             //打印标签及其p_decode=========================================================================================
            // printf("index1:%s\n",p_decode);  
            // 存起来
            p_decode_1[p] = p_decode;     	    
            cscbf.insertion(to_string(1),p_decode);

            
            if (cscbf.obfquery(0, p_decode) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode] = p;
                count_test1++;
            }

           

            // int res = 1;
            // for (int set_ID = 1; set_ID < num; set_ID++)
            // {
            //     // int cscbf_res = cscbf.query(set_ID,p_decode);
            //     int cscbf_res = cscbf.obfquery(set_ID,p_decode);
            //     res &= cscbf_res;
            //     if(!res){
            //         break;
            //     }
                    
            // }
            // if(res){
            //     result1[p_decode] = p;
            // }
        }
         // 打印 交集个数 的值
        printf("交集个数: %d\n", count_test1);
        printf("p_decode_1 elements: ");
        for (const auto& elem : p_decode_1) {
            printf("%s, ", elem.c_str());
        }
        printf("\n");

        int count_test0=0;
        // 验证集合0的是否在集合1当中
        for (int p = 0; p < len0; p++)
        {
            string p_decode = p_decode_0[p];
            if (cscbf.obfquery(1, p_decode) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode] = p;
                count_test0++;
            }
        }
        // 打印 交集个数 的值
        printf("交集个数: %d\n", count_test0);


        // Oblivious Selection
        vector<string> Result_0;
        vector<string> Result_1;
        int count_test3=0;
        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
                count_test3++;

            }
            else
                Result_0.push_back("0"); // 如果 ResultVector_0[p] 为 0，则推入字符串 "0"
        }
        // 打印 交集个数 的值
        printf("Result0交集个数: %d\n", count_test3);

        // // Print all elements of IntersectResult_1 in a single line
        //     printf("Result_0: ");
        //     for (const auto& elem : Result_0) {
        //         printf("%s, ", elem.c_str());
        //     }
        //     printf("\n");

        vector<pair<string, int>> F_0;
        count = 0; // 记录交集元素的数量，最终数量应该是count+1
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1)); // 如果是0，那么就推入000||-1
            }
        }
        // 打印 F0.size 的值
        printf("F0: %d\n", F_0.size());  
        // 打印 count 的值
        printf("Count in Set0: %d\n", count);  
        int chunknumber = F_0.size() / (count)+1; // 记得加1，相当于向上取整
        printf("chunknumber: %d\n", chunknumber);  
        vector<vector<pair<string, int>>> Chunks0(chunknumber);

        // 分块处理
        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        //  给最后一个不满的chunk填充0
        while (Chunks0.back().size() < count) // 定位到Chunks中最后一个Chunk的size
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }
        
        // //打印chunk0
        // for (int h = 0; h < chunknumber; h++)
        // {
        //     printf("Chunk %d before Oblivious Sort:\n", h);
        // for (const auto& elem : Chunks0[h])
        //     {   
        //         printf("(%s, %d) ", elem.first.c_str(), elem.second);
        //     }
        //     printf("\n");
        // }

        // 进行Oblivious Sort
        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);//s=======================是count还是count+1
            //         // 打印排序后的每个Chunk的内容
            // printf("Chunk %d after Oblivious Sort:\n", h);
            // for (const auto& elem : Chunks0[h])
            // {
            //     printf("(%s, %d) ", elem.first.c_str(), elem.second);
            // }
            // printf("\n");
        }

        // 从每个块中选择不为0的元素
        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first; // 直接在对应位置更新值
                }
            }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
                Result_1.push_back(p_decode_1[p]);
            else
                Result_1.push_back("0");
        }

        vector<pair<string, int>> F_1;
        count = 0; // 记录交集元素的数量，最终数量应该是count+1
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1)); // 如果是0，那么就推入000||-1
            }
        }
        // 打印 count 的值
        printf("Count in Set1: %d\n", count);
        chunknumber = F_1.size() / (count)+1; // 记得加1，相当于向上取整
                // 打印F_1每个元素的内容
        printf("Elements of F_1:\n");
        for (const auto& elem : F_1)
        {
            printf("(%s, %d) ", elem.first.c_str(), elem.second);
        }
        printf("\n");




        vector<vector<pair<string, int>>> Chunks1(chunknumber);

        // 分块处理
        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * (count) + j]);
            }

        //  给最后一个不满的chunk填充0
        while (Chunks1.back().size() < count) // 定位到Chunks中最后一个Chunk的size
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }


         //打印chunk1
        for (int h = 0; h < chunknumber; h++)
        {
            printf("Chunk %d before Oblivious Sort:\n", h);
        for (const auto& elem : Chunks1[h])
            {   
                printf("(%s, %d) ", elem.first.c_str(), elem.second);
            }
            printf("\n");
        }

        // 进行Oblivious Sort
        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
            printf("Chunk %d after Oblivious Sort:\n", h);
            for (const auto& elem : Chunks1[h])
            {
                printf("(%s, %d) ", elem.first.c_str(), elem.second);
            }
            printf("\n");
        }



        // 从每个块中选择不为0的元素
        IntersectResult_1.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first; // 直接在对应位置更新值
                }
            }


            // Print all elements of IntersectResult_0 in a single line
            printf("IntersectResult_0 elements: ");
            for (const auto& elem : IntersectResult_0) {
                printf("%s, ", elem.c_str());
            }
            printf("\n");

            // Print all elements of IntersectResult_1 in a single line
            printf("IntersectResult_1 elements: ");
            for (const auto& elem : IntersectResult_1) {
                printf("%s, ", elem.c_str());
            }
            printf("\n");





    }       

    if(num == 3 || num == 5 || num == 10){
        int len2 = 0;
        ocall_read_eneq2(&len2,ein2);
        for(int p=0;p<len1;p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2,iv1, p_decode_base64);
            printf("index1:%s\n",p_decode);       	    
            cscbf.insertion(to_string(1),p_decode);
        }
        if(num == 3){
            for(int p=0;p<len2;p++)
            {
                string enindex = ein2[p];
                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2,iv2,p_decode_base64);
                printf("index2:%s,",p_decode);       	    
                cscbf.insertion(to_string(2),p_decode);

                int res = 1;
                for (int set_ID = 1; set_ID < num; set_ID++)
                {
                    int cscbf_res = cscbf.query(set_ID,p_decode);
                    // int cscbf_res = cscbf.obfquery(set_ID,p_decode);
                    res &= cscbf_res;
                    if(!res){
                        break;
                    }
                        
                }
                if(res){
                    result1[p_decode] = p;
                }
            }
        } else{
            int len3 = 0;
            ocall_read_eneq3(&len3,ein3);
            int len4 = 0;
            ocall_read_eneq4(&len4,ein4);
            for(int p=0;p<len2;p++)
            {
                string enindex = ein2[p];
                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2,iv2,p_decode_base64);
                printf("index2:%s,",p_decode);       	    
                cscbf.insertion(to_string(2),p_decode);
            }
            for(int p=0;p<len3;p++)
            {
                string enindex = ein3[p];
                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2,iv3,p_decode_base64);
                printf("index3:%s,",p_decode);       	    
                cscbf.insertion(to_string(3),p_decode);
            }            
            if(num == 5){
                for(int p=0;p<len4;p++)
                {
                    string enindex = ein4[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv4,p_decode_base64);
                    printf("index4:%s,",p_decode);       	    
                    cscbf.insertion(to_string(4),p_decode);

                    int res = 1;
                    for (int set_ID = 1; set_ID < num; set_ID++)
                    {
                        int cscbf_res = cscbf.query(set_ID,p_decode);
                        // int cscbf_res = cscbf.obfquery(set_ID,p_decode);
                        res &= cscbf_res;
                        if(!res){
                            break;
                        }
                            
                    }
                    if(res){
                        result1[p_decode] = p;
                    }
                }
            } else{
                int len5 = 0;
                ocall_read_eneq5(&len5,ein5);
                int len6 = 0;
                ocall_read_eneq6(&len6,ein6);
                int len7 = 0;
                ocall_read_eneq7(&len7,ein7);
                int len8 = 0;
                ocall_read_eneq8(&len8,ein8);
                int len9 = 0;
                ocall_read_eneq9(&len9,ein9);
                for(int p=0;p<len4;p++)
                {
                    string enindex = ein4[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv4,p_decode_base64);
                    printf("index4:%s,",p_decode);       	    
                    cscbf.insertion(to_string(4),p_decode);
                }                
                for(int p=0;p<len5;p++)
                {
                    string enindex = ein5[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv5,p_decode_base64);
                    printf("index5:%s,",p_decode);       	    
                    cscbf.insertion(to_string(5),p_decode);
                }
                for(int p=0;p<len6;p++)
                {
                    string enindex = ein6[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv6,p_decode_base64);
                    printf("index6:%s,",p_decode);       	    
                    cscbf.insertion(to_string(6),p_decode);
                }
                for(int p=0;p<len7;p++)
                {
                    string enindex = ein7[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv7,p_decode_base64);
                    printf("index7:%s,",p_decode);       	    
                    cscbf.insertion(to_string(7),p_decode);
                }
                for(int p=0;p<len8;p++)
                {
                    string enindex = ein8[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv8,p_decode_base64);
                    printf("index8:%s,",p_decode);       	    
                    cscbf.insertion(to_string(8),p_decode);
                }
                for(int p=0;p<len9;p++)
                {
                    string enindex = ein9[p];
                    string p_decode_base64 = base64_decode(enindex);
                    string p_decode = aes_256_cbc_decode(cbc_key2,iv9,p_decode_base64);
                    printf("index9:%s,",p_decode);       	    
                    cscbf.insertion(to_string(9),p_decode);

                    int res = 1;
                    for (int set_ID = 1; set_ID < num; set_ID++)
                    {
                        int cscbf_res = cscbf.query(set_ID,p_decode);
                        // int cscbf_res = cscbf.obfquery(set_ID,p_decode);
                        res &= cscbf_res;
                        if(!res){
                            break;
                        }
                            
                    }
                    if(res){
                        result1[p_decode] = p;
                    }
                }
            }
        }
    }


    // 定义最终结果集
    vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
    int k;

    for (auto fi : IntersectResult_0)
    {
        k = 0;
        if (result0.find(fi) != result0.end())
        {
            for (auto fj : IntersectResult_1)
            {
                if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                {
                    FinalResult[k] = make_pair(result0[fi], result1[fj]);
                    // // 打印出 fj 的值
                    // printf("fj:\n");
                    // printf("fj: %s", fj.c_str());
                    ocall_write_result(atoi(fj.c_str()));
                    ocall_writeendl_result();
                }
                k++; // 遍历最终结果集
            }
        }
    }
    e2 = sgx_clock();
    printf("\nsbf执行时间: %f us\n", (double)((e2 - s2)));
    ocall_close_enquery();
    ocall_close_result();

    // //index存的就是p_decode
    // for(int j=0;j<index.size();j++)
    // {
	//     if(result1.find(index[j]) != result1.end())
    //         result0[index[j]] = j;
        
    // }

    // unordered_map<string,int> HTE;
    // for(auto h1 : result0)
    // {
    //     HTE[h1.first] = h1.second;
    // }
    // for(auto h2 : result1)
    // {
    //     if(HTE.find(h2.first) != HTE.end())
    //     {
    //         storage2.push_back(pair<int,int>(HTE[h2.first],h2.second));
    //         //测试的时候注释掉
    //         ocall_write_result(atoi(h2.first.c_str()));
    //         ocall_writeendl_result();
    //     }
    // }

    // e2 = sgx_clock();
    // printf("\nsbf执行时间: %f us\n", (double)((e2 - s2)));

    // ocall_close_enquery();
    // ocall_close_result();
}
