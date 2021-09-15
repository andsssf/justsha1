namespace justsha1 {
    typedef unsigned char BYTE;
    typedef unsigned int WORD;
    typedef unsigned long long DWORD;
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
        BYTE data[64];
        DWORD data_size;
        DWORD total_size;
        bool computerOneBlock();
        bool padingDataBlock();
    };
}
