#include "justsha1/sha1.h"
#include <iostream>

using namespace std;

int main() {
    __UINT8_TYPE__ result[20] = {0};
    sha1("abc", result);
    return 0;
}
