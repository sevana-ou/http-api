#include "http_api.h"

#include <iostream>

int main(int argc, char** argv)
{
    http_client client;
    std::atomic_bool exit_flag(false);

    client.get("http://voipobjects.com/", [&exit_flag](http_client& /*client*/, http_client::ctx /*ctx*/, http_client::response_info& info)
    {
        if (info.mChunk.size() == 0)
        {
            std::cout << "Code:    " << info.mCode << std::endl
                      << "Length:  " << info.mAllData.size() << std::endl
                      << info.mAllData << std::endl;
            exit_flag = true;
        }
    });

    // Loop enough time
    while (!exit_flag)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
