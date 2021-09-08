#include "justsha1/sha1.h"
#include <iostream>

using namespace std;

int main() {
    char result[41] = {0};
    if (justsha1::sha1("justsha1", result)) {
        cout << string(result)  << endl;
    }
    return 0;
}
