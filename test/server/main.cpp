#include "dashboard.h"
#include <chrono>
#include <thread>

int main(int /*argc*/, const char** /*argv*/)
{
    // Run server
    std::atomic_bool exit_flag; exit_flag = false;
    dashboard_start(8080, exit_flag);

    // Wait for 60 seconds & exit
    while (!exit_flag)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    dashboard_stop();
    return EXIT_SUCCESS;
}
