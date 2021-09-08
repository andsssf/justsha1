#include "justsha1/sha1.h"
#include <iostream>

using namespace std;
using namespace justsha1;

int main() {
    char result[41] = {0};
    Sha1 s;
    bool flag = s.update("justsha1");
    if (flag) {
        s.getResultString(result);
        cout << string(result)  << endl;
    }
    return 0;
}
