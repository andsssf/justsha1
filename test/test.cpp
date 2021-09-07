#include "justsha1/sha1.h"
#include <iostream>

using namespace std;

int main() {
    char result_str[20] = {0};
    sha1("justsha1", result_str);
    cout << result_str << endl;
    return 0;
}
