#include "http_api.h"

#include <iostream>

int main(int /*argc*/, char** /*argv*/)
{
    http_client client;
    std::atomic_bool exit_flag(false);

    // Test simple GET
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

    exit_flag = false;
    std::atomic_int timer_counter(0);

    // Test timer
    timer tmr_1(client.getIoContext(), std::chrono::milliseconds(5000), timer::flag_interval_with_immediate, [&timer_counter, &client]()
    {
        std::cout << "Current UNIX timestamp: " << time(nullptr) << std::endl;
        timer_counter++;

        // Test simple GET
        client.get("http://voipobjects.com/", [](http_client& /*client*/, http_client::ctx /*ctx*/, http_client::response_info& info)
        {
            if (info.mChunk.size() == 0)
            {
                std::cout << "Code:    " << info.mCode << std::endl
                          << "Length:  " << info.mAllData.size() << std::endl
                          << info.mAllData << std::endl;
            }
        });

    });

    // Wait for 3 attempts
    while (timer_counter < 3)
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    return EXIT_SUCCESS;
}
