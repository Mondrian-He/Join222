#ifndef _BLOOMFILTER_
#define _BLOOMFILTER_
#include <vector>
#include <iostream>
#include <cstring>
#include <random>

#include "bitarray.h"
#include "MurmurHash3.h"

using namespace std;

vector<size_t> BF_Hash(string key, int k, size_t* seed, size_t single_capacity){

    vector<size_t> hash_value;
    size_t op;

    for(int i=0; i<k; i++){
        MurmurHash3_x86_128(key.c_str(), key.size(), seed[i], &op);
        hash_value.push_back(op%single_capacity);
    }
    return hash_value;
}

// std::vector<size_t> BF_Hash(std::string key, int k, size_t* seed, size_t single_capacity);

class BloomFilter{
    public:
        // BloomFilter(size_t size, size_t k);
        // void insert(std::vector<size_t> a);
        // bool check(std::vector<size_t> a);

        size_t k;
        size_t capacity;
        size_t time_ins;

        bitarray* bits_;

        BloomFilter(size_t size, size_t k){
            
            this->k = k;
            this->bits_ = new bitarray(size);
            this->capacity = size;
            this->time_ins = 0;
        }

        void insert(vector<size_t> a){
            int N = a.size();
            for(int n=0; n<N; n++){
                this->bits_->setbit(a[n]);
                this->time_ins ++;
            }
        }

        bool check(vector<size_t> a){
            int N = a.size();
            for (int n =0 ; n<N; n++){
                if (!this->bits_->checkbit(a[n])){
                    return false;
                }
            }
            return true;
        }

};

#endif