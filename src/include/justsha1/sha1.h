typedef __UINT8_TYPE__ BYTE;
typedef __UINT32_TYPE__ WORD;
typedef __UINT64_TYPE__ DWORD;

namespace justsha1 {
    class Sha1 {
        public:
        Sha1();
        void reset();
        bool update(const BYTE * input, DWORD size);
        bool update(const char * input);
        void getDigest(BYTE * output);
        void getDigestString(char * output, bool toUpperCase = false);
        private:
        WORD A, B, C, D, E;
        bool isBigEnd;
        bool isFinish;
    };
}
