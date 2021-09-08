namespace justsha1 {

    bool sha1(const char * input, char * output, bool toUpperCase = false);

    bool sha1(const __UINT8_TYPE__ * input, __UINT64_TYPE__ size,  __UINT8_TYPE__ * output);
}
