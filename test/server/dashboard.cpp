#include "dashboard.h"
#include "http_api.h"

#include <memory>
#include <chrono>
#include <string>
#include <sstream>

using namespace std::chrono;
static std::shared_ptr<http_server> DashboardServer;
static time_point<steady_clock> StartTime = steady_clock::now();

const std::string Html_Ok = "<html><body>"
                            "<p>Status:  {status}    </p>"
                            "<p>Message: {message}   </p>"
                            "<p>Headers: {headers}   </p>"
                            "<p>Thread:  {thread_id} </p>"
                            "</body></html>";

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
            // Get current thread id
            std::ostringstream id_stream; id_stream << std::this_thread::get_id();

            // Send minimal answer
            std::map<std::string, std::string> vars = {
                {"status",      "ok"},
                {"message",     "answered"},
                {"thread_id",   id_stream.str()}
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
        if (info.mMethod == Method_POST)
        {
            // Echo sent parameters
            std::ostringstream oss; oss << "<html><body>";
            for (const auto& p: info.mParams)
                oss << "<p>" << p.first << ": " << p.second << "</p>" << std::endl;
            oss << "</body></html>";
            server.send_html(ctx, oss.str());
        }
        else
            server.send_error(ctx, 405);
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
