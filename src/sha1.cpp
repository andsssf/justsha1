#include "justsha1/sha1.h"
#include <cstring>

using namespace justsha1;

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

WORD bigMode(WORD value) {
    return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 | (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24; 
}

DWORD bigMode(DWORD value) {
    DWORD high_uint64 = (DWORD)bigMode((WORD)value);
    DWORD low_uint64 = (DWORD)bigMode((WORD)(value >> 32));
    return (high_uint64 << 32) + low_uint64;
}

Sha1::Sha1() {
    this->isBigEnd = isBigEndian();
    this->reset();
}

void Sha1::reset() {
    this->A = isBigEnd ? 0x67452301 : bigMode((WORD)0x67452301);
    this->B = isBigEnd ? 0xEFCDAB89 : bigMode((WORD)0xEFCDAB89);
    this->C = isBigEnd ? 0x98BADCFE : bigMode((WORD)0x98BADCFE);
    this->D = isBigEnd ? 0x10325476 : bigMode((WORD)0x10325476);
    this->E = isBigEnd ? 0xC3D2E1F0 : bigMode((WORD)0xC3D2E1F0);

    this->isFinish = false;
    memset(data, 0, 64);
    data_size = 0;
    total_size = 0;
}

bool Sha1::computerOneBlock() {
    WORD k[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
    if (!isBigEnd) {
        for (int i = 0; i < 4; i++) k[i] = bigMode(k[i]);
    }
    
    WORD sub_group[80] = {0};
    WORD * temp_sub_group = (WORD*)(data);  // 定位子组 0-15 的数据
    
    // 生成子组
    for (int j = 0; j < 80; j++) {
        if (j < 16) sub_group[j] = temp_sub_group[j];
        else {
            WORD temp = sub_group[j - 3] ^ sub_group[j - 8] ^ sub_group[j - 14] ^ sub_group[j - 16];
            temp = isBigEnd ? temp : bigMode(temp);
            sub_group[j] = isBigEnd ? temp << 1 | temp >> 31 : bigMode(temp << 1 | temp >> 31);
        }
    }

    WORD a = A, b = B, c = C, d = D, e = E;

    for (int j = 0; j < 80; j++) {
        WORD temp, temp2 = isBigEnd ? a << 5 | a >> 27 : bigMode(bigMode(a) << 5 | bigMode(a) >> 27);
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

    return true;
}

bool Sha1::update(const BYTE * input, DWORD size) {
    if (isFinish) return false;
    DWORD index = 0;
    while (data_size + size > 64) {
        memcpy(data + data_size, input + index, 64 - data_size);
        computerOneBlock();
        size -= 64 - data_size;
        index += 64 - data_size;
        total_size += 64 - data_size;
        data_size = 0;
    }
    memcpy(data + data_size, input + index, size);
    data_size += size;
    total_size += size;
    if (data_size == 64) {
        computerOneBlock();
        data_size = 0;
    }
    return true;
}

bool Sha1::update(const char * input) {
    return update((const BYTE *)input, strlen(input));
}

void Sha1::getDigest(BYTE * output) {
    if (!isFinish) {
        padingDataBlock();
        computerOneBlock();
    }

    *(__UINT32_TYPE__*)output = A;
    *(__UINT32_TYPE__*)(output + 4) = B;
    *(__UINT32_TYPE__*)(output + 8) = C;
    *(__UINT32_TYPE__*)(output + 12) = D;
    *(__UINT32_TYPE__*)(output + 16) = E;
}

void Sha1::getDigestString(char * output, bool toUpperCase) {
    BYTE origin_output[20];
    getDigest(origin_output);

    size_t index = 0;
    for (BYTE c : origin_output) {
        char high = c / 16, low = c % 16;
        output[index] = high < 10 ? '0' + high : (toUpperCase ? 'A' : 'a' + high - 10);
        output[index + 1] = low < 10 ? '0' + low : (toUpperCase ? 'A' : 'a' + low - 10);
        index += 2;
    }
}

bool Sha1::padingDataBlock() {
    if (isFinish) return false;
    if (data_size != 56) {
        DWORD pad_size = (64 + 56 - data_size) % 64;
        if (data_size + pad_size < 64) {
            data[data_size] = 0x80;
            memset(data + data_size + 1, 0x0, pad_size - 1);
        } else {
            data[data_size] = 0x80;
            memset(data + data_size + 1, 0x0, 64 - data_size - 1);
            computerOneBlock();
            memset(data, 0x0, 56);
        }
    }

    *(DWORD*)(data + 56) = isBigEnd ? total_size * 8 : bigMode(total_size * 8);
    isFinish = true;
    return true;
}
