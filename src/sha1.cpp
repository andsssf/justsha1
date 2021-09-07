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

bool sha1(const char * input, __UINT8_TYPE__ * output) {
    __UINT32_TYPE__ A = 0x67452301;
    __UINT32_TYPE__ B = 0xEFCDAB89;
    __UINT32_TYPE__ C = 0x98BADCFE;
    __UINT32_TYPE__ D = 0x10325476;
    __UINT32_TYPE__ E = 0xC3D2E1F0;

    __UINT32_TYPE__ k[4] = {0x5A827999, 0x6ED9EBA1, 0x8F188CDC, 0xCA62C1D6};

    __UINT64_TYPE__ size = strlen(input) * 8;
    __UINT8_TYPE__ * data = nullptr;
    __UINT64_TYPE__ total_size = 0;
    bool isBigEnd = isBigEndian();
    
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

    // 添加原长度信息，原本是小端存储，需要转换为大端存储
    // __UINT8_TYPE__ *p = (__UINT8_TYPE__*)&size;
    // // int64 有8个字节
    // for (int i = 0; i < 8; i++) {
    //     data[total_size / 8 - 1 - i] = *(p + i);
    // }

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
                temp += k[0];
                break;
            case 1:
                temp = (b  ^ c ^ d);
                temp += k[1];
                break;
            case 2:
                temp = (b & c) | (b & d) | (c & d);
                temp += k[2];
                break;
            case 3:
                temp = (b ^ c ^ d);
                temp += k[3];
                break;
            }
            temp += temp2 + e + sub_group[j];
            e = d;
            d = c;
            c = isBigEnd ? b << 30 | b >> 2 : bigMode(bigMode(b) << 30 | bigMode(b) >> 2);
            b = a;
            a = temp;
        }
        A += a;
        B += b;
        C += c;
        D += d;
        E += e;
    }

    delete []data;

    *(__UINT32_TYPE__*)output = A;
    *(__UINT32_TYPE__*)(output + 4) = B;
    *(__UINT32_TYPE__*)(output + 8) = C;
    *(__UINT32_TYPE__*)(output + 12) = D;
    *(__UINT32_TYPE__*)(output + 16) = E;

    return false;
}
