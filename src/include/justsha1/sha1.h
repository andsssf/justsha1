namespace justsha1 {
    class Sha1 {
        public:
        Sha1();
        void reset();
        bool update(const __UINT8_TYPE__ * input, __UINT64_TYPE__ size);
        bool update(const char * input);
        void getResult(__UINT8_TYPE__ * output);
        void getResultString(char * output, bool toUpperCase = false);
        private:
        __UINT32_TYPE__ A, B, C, D, E;
        bool isBigEnd;
    };
}
