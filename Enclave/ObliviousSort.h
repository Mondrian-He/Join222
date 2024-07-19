#ifndef OBLIVIOUS_SORT_H
#define OBLIVIOUS_SORT_H

#include <vector>
#include <string>
#include <utility>
#include <algorithm>
#include <climits>
#include <unordered_set>

// 比较交换
bool compare_and_swap(std::pair<std::string, int>& a, std::pair<std::string, int>& b, int dir) {
    if (dir == (a.second > b.second)) {
        std::swap(a, b);
        return true;
    }
    return false;
}

// 比特onic合并函数
void bitonic_merge(std::vector<std::pair<std::string, int>>& arr, int low, int cnt, int dir) {
    if (cnt > 1) {
        int k = cnt / 2;
        for (int i = low; i < low + k; i++) {
            compare_and_swap(arr[i], arr[i + k], dir);
        }
        bitonic_merge(arr, low, k, dir);
        bitonic_merge(arr, low + k, k, dir);
    }
}

// 比特onic排序函数
void bitonic_sort(std::vector<std::pair<std::string, int>>& arr, int low, int cnt, int dir) {
    if (cnt > 1) {
        int k = cnt / 2;
        bitonic_sort(arr, low, k, 1);  // 升序
        bitonic_sort(arr, low + k, k, 0);  // 降序
        bitonic_merge(arr, low, cnt, dir);
    }
}

// 填充到最近的2的幂次方大小
void pad_to_power_of_two(std::vector<std::pair<std::string, int>>& arr) {
    int N = arr.size();
    int new_N = 1;
    while (new_N < N) {
        new_N <<= 1;
    }
    arr.resize(new_N, {"", INT_MAX});
}

// 对每个chunk中的000元素进行标号
void check_and_label_seconds(std::vector<std::pair<std::string, int>>& arr, int count) {
    std::unordered_set<int> existing;
    for (const auto& elem : arr) {
        if (elem.second >= 0 && elem.second <= count) {
            existing.insert(elem.second);
        }
    }
    
    int label = 0;
    for (auto& elem : arr) {
        if (elem.second < 0 || elem.second > count) {
            while (existing.find(label) != existing.end()) {
                label++;
            }
            elem.second = label;
            existing.insert(label);
        }
    }
}


void Oblivious(std::vector<std::pair<std::string, int>>& arr, int count) {
    check_and_label_seconds(arr, count);
    pad_to_power_of_two(arr);
    int N = arr.size();
    int up = 1;  // 1表示升序，0表示降序
    bitonic_sort(arr, 0, N, up);
}

#endif // OBLIVIOUS_SORT_H
