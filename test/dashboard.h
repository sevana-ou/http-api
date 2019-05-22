#ifndef __DASHBOARD_H
#define __DASHBOARD_H

#include <atomic>

extern void dashboard_start(int port, std::atomic_bool& exit_flag);
extern void dashboard_stop();

#endif
