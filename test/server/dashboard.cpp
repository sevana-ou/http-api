#include "dashboard.h"
#include "http_api.h"

#include <memory>
#include <chrono>
#include <string>
#include <sstream>

using namespace std::chrono;
static std::shared_ptr<http_server> DashboardServer;
static time_point<steady_clock> StartTime = steady_clock::now();

const std::string Html_Ok = "<html><body><p>Status: {status}</p><p>Message: {message}</p><p>Headers:</p>{headers}</body></html>";

static std::string apply_vars(const std::string& templ, const std::map<std::string, std::string>& vars)
{
    std::string r = templ;

    for (auto iter: vars)
    {
        std::string varname = "{" + iter.first + "}";
        std::string::size_type p = r.find(varname);
        if (p != std::string::npos)
        {
            r.erase(p, varname.size());
            r.insert(p, iter.second);
        }
    }

    return r;
}

void dashboard_start(int port, std::atomic_bool& exit_flag)
{
    if (!port)
        return;

    DashboardServer = std::make_shared<http_server>();
    DashboardServer->setPort(static_cast<uint16_t>(port));
    DashboardServer->set_handler([&exit_flag](http_server& server, http_server::ctx ctx, const http_server::request_info& info)
    {
        if (info.mMethod == Method_GET)
        {
            std::map<std::string, std::string> vars = {
                {"status",      "ok"},
                {"message",     "answered"}
            };

            std::ostringstream oss;
            for (const auto& hdr: info.mHeaders)
                oss << "<p>" << hdr.first << ": " << hdr.second << "</p>";
            vars["headers"] = oss.str();

            server.send_html(ctx, apply_vars(Html_Ok, vars));
            if (info.mPath.find("quit") != std::string::npos)
                exit_flag = true;
        }
        else
            server.send_error(ctx, 404);
    });

    DashboardServer->start();
}

void dashboard_stop()
{
    if (DashboardServer)
    {
        DashboardServer->stop();
        DashboardServer.reset();
    }
}
