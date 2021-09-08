#include "justsha1/sha1.h"
#include <cstring>

// 机器大小端模式是个问题，主要是位移运算的不一致性
bool isBigEndian(){
    union{
        int a;  
        char b;  
    }num;  
    num.a = 0x1234;  
    if( num.b == 0x12){  
        return true;  
    }
    return false;  
}

__UINT32_TYPE__ bigMode(__UINT32_TYPE__ value) {
    return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 | (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24; 
}

__UINT64_TYPE__ bigMode(__UINT64_TYPE__ value) {
    __UINT64_TYPE__ high_uint64 = (__UINT64_TYPE__)bigMode((__UINT32_TYPE__)value);
    __UINT64_TYPE__ low_uint64 = (__UINT64_TYPE__)bigMode((__UINT32_TYPE__)(value >> 32));
    return (high_uint64 << 32) + low_uint64;
}

justsha1::Sha1::Sha1() {
    this->isBigEnd = isBigEndian();
    this->reset();
}

void justsha1::Sha1::reset() {
    this->A = isBigEnd ? 0x67452301 : bigMode((__UINT32_TYPE__)0x67452301);
    this->B = isBigEnd ? 0xEFCDAB89 : bigMode((__UINT32_TYPE__)0xEFCDAB89);
    this->C = isBigEnd ? 0x98BADCFE : bigMode((__UINT32_TYPE__)0x98BADCFE);
    this->D = isBigEnd ? 0x10325476 : bigMode((__UINT32_TYPE__)0x10325476);
    this->E = isBigEnd ? 0xC3D2E1F0 : bigMode((__UINT32_TYPE__)0xC3D2E1F0);
}

bool justsha1::Sha1::update(const __UINT8_TYPE__ * input, __UINT64_TYPE__ size) {
    __UINT32_TYPE__ k[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

    if (!isBigEnd) {
        for (int i = 0; i < 4; i++) k[i] = bigMode(k[i]);
    }

    size *= 8;
    __UINT8_TYPE__ * data = nullptr;
    __UINT64_TYPE__ total_size = 0;
    
    if (size % 512 != 448) {
        __int64 x = (512 + 448 - size % 512) % 512;
        data = new __UINT8_TYPE__[(size + x) / 8 + 8];
        memset(data, 0x0, (size + x) / 8 + 8);
        total_size = size + x + 64;
        // 数据拷贝
        for (int i = 0; i < size / 8; i++) data[i] = input[i];
        // 补位
        data[size / 8] = 0x80;
    } else {
        data = new __UINT8_TYPE__[size / 8 + 8];
        memset(data, 0x0, size / 8 + 8);
        total_size = size + 64;
        // 数据拷贝
        for (int i = 0; i < size / 8; i++) data[i] = input[i];
    }

    *(__UINT64_TYPE__*)(data + total_size / 8 - 8) = isBigEnd ? size : bigMode(size);

    __UINT64_TYPE__ num_group = total_size / 512;

    for (int i = 0; i < num_group; i++) {
        __UINT32_TYPE__ sub_group[80] = {0};
        __UINT32_TYPE__ * temp_sub_group = (__UINT32_TYPE__*)(data + i*64);  // 定位子组 0-15 的数据
        
        // 生成子组
        for (int j = 0; j < 80; j++) {
            if (j < 16) sub_group[j] = temp_sub_group[j];
            else {
                __UINT32_TYPE__ temp = sub_group[j - 3] ^ sub_group[j - 8] ^ sub_group[j - 14] ^ sub_group[j - 16];
                temp = isBigEnd ? temp : bigMode(temp);
                sub_group[j] = isBigEnd ? temp << 1 | temp >> 31 : bigMode(temp << 1 | temp >> 31);
            }
        }

        __UINT32_TYPE__ a = A, b = B, c = C, d = D, e = E;

        for (int j = 0; j < 80; j++) {
            __UINT32_TYPE__ temp, temp2 = isBigEnd ? a << 5 | a >> 27 : bigMode(bigMode(a) << 5 | bigMode(a) >> 27);
            switch (j / 20)
            {
            case 0:
                temp = (b & c) | ((~b) & d);
                temp = isBigEnd ? k[0] + temp : bigMode(bigMode(k[0]) + bigMode(temp));
                break;
            case 1:
                temp = (b ^ c ^ d);
                temp = isBigEnd ? k[1] + temp : bigMode(bigMode(k[1]) + bigMode(temp));
                break;
            case 2:
                temp = (b & c) | (b & d) | (c & d);
                temp = isBigEnd ? k[2] + temp : bigMode(bigMode(k[2]) + bigMode(temp));
                break;
            case 3:
                temp = (b ^ c ^ d);
                temp = isBigEnd ? k[3] + temp : bigMode(bigMode(k[3]) + bigMode(temp));
                break;
            }
            temp = isBigEnd ? temp + temp2 + e + sub_group[j] : bigMode(bigMode(temp) + bigMode(temp2) + bigMode(e) + bigMode(sub_group[j]));
            e = d;
            d = c;
            c = isBigEnd ? b << 30 | b >> 2 : bigMode(bigMode(b) << 30 | bigMode(b) >> 2);
            b = a;
            a = temp;
        }
        A = isBigEnd? A + a  : bigMode(bigMode(a) + bigMode(A));
        B = isBigEnd? B + b  : bigMode(bigMode(b) + bigMode(B));
        C = isBigEnd? C + c  : bigMode(bigMode(c) + bigMode(C));
        D = isBigEnd? D + d  : bigMode(bigMode(d) + bigMode(D));
        E = isBigEnd? E + e  : bigMode(bigMode(e) + bigMode(E));
    }

    delete []data;
    return true;
}

bool justsha1::Sha1::update(const char * input) {
    return update((const __UINT8_TYPE__ *)input, strlen(input));
}

void justsha1::Sha1::getResult(__UINT8_TYPE__ * output) {
    *(__UINT32_TYPE__*)output = A;
    *(__UINT32_TYPE__*)(output + 4) = B;
    *(__UINT32_TYPE__*)(output + 8) = C;
    *(__UINT32_TYPE__*)(output + 12) = D;
    *(__UINT32_TYPE__*)(output + 16) = E;
}

void justsha1::Sha1::getResultString(char * output, bool toUpperCase) {
    __UINT8_TYPE__ origin_output[20];
    getResult(origin_output);

    size_t index = 0;
    for (__UINT8_TYPE__ c : origin_output) {
        char high = c / 16, low = c % 16;
        output[index] = high < 10 ? '0' + high : (toUpperCase ? 'A' : 'a' + high - 10);
        output[index + 1] = low < 10 ? '0' + low : (toUpperCase ? 'A' : 'a' + low - 10);
        index += 2;
    }
}
