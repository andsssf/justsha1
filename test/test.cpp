#include "justsha1/sha1.h"
#include <iostream>
#include <fstream>
#include <cstring>

using namespace std;
using namespace justsha1;

int main(int argc, char* argv[]) {
    if (argc > 2) return -1;
    if (!strcmp(argv[1], "string_test")) {
        char result[41] = {0};
        Sha1 s;
        bool flag1 = s.update("just");
        bool flag2 = s.update("sha1");
        if (flag1 && flag2) {
            s.getDigestString(result);
            cout << string(result)  << endl;
        }
    } else if (!strcmp(argv[1], "file_test")){
        ifstream fin;
        fin.open("Makefile", ios::binary | ios::ate);
        if (!fin.is_open()) return -1;
        DWORD size = fin.tellg();
        fin.seekg(0, ios::beg);
        char buffer[512];
        Sha1 s;
        for (int i = 0; i < size / 512; i++) {
            fin.read(buffer, 512);
            s.update((BYTE *)buffer, 512);
        }
        fin.read(buffer, size % 512);
        fin.close();
        s.update((BYTE *)buffer, size % 512);

        char result[41];
        s.getDigestString(result);
        cout << result << endl;
    } else return -1;
    return 0;
}
