#include "dashboard.h"
#include "http_api.h"

#include <memory>
#include <chrono>
#include <string>
#include <sstream>
#include <algorithm>
#include <iostream>

using namespace std::chrono;

#if defined(ENABLE_MULTI_THREAD_SERVER)
typedef http_server_multi my_http_server;
#else
typedef http_server my_http_server;
#endif

static std::shared_ptr<my_http_server> DashboardServer;
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

static std::shared_ptr<std::thread> delayed_thread;
static std::mutex alive_requests_mutex;
static std::set<my_http_server::ctx> alive_requests;

void dashboard_start(int port, std::atomic_bool& exit_flag)
{
    if (!port)
        return;

    DashboardServer = std::make_shared<my_http_server>();
    DashboardServer->setPort(static_cast<uint16_t>(port));

    DashboardServer->set_handler([](my_http_server& /*server*/, my_http_server::ctx ctx)
    {
        std::unique_lock<std::mutex> l(alive_requests_mutex);

        auto iter = alive_requests.find(ctx);
        if (iter != alive_requests.end())
            alive_requests.erase(iter);

        std::cout << "Request is finished." << std::endl;
    });

    DashboardServer->set_handler([&exit_flag](my_http_server& server, http_server::ctx ctx, const request_info& info)
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

            if (info.mPath == "/" || info.mPath == "/html")
            {
                std::ostringstream oss;
                for (const auto& hdr: info.mHeaders)
                    oss << "<p>" << hdr.first << ": " << hdr.second << "</p>";
                vars["headers"] = oss.str();
                server.send_html(ctx, apply_vars(Html_Ok, vars));
            }
            if (info.mPath == "/json" || info.mPath == "/json_chunked")
            {
                std::ostringstream oss;
                oss << "{" << std::endl;
                for (const auto& iter: vars)
                {
                    oss << "\"" << iter.first << "\": \"" << iter.second << "\"," << std::endl;
                }
                oss << "\"stub\": \"\"" << std::endl << "}";

                if (info.mPath == "/json")
                    server.send_json(ctx, oss.str());
                else
                {
                    server.send_chunk_reply(ctx, 200);
                    std::string answer = oss.str();
                    size_t sent_bytes = 0;
                    while (sent_bytes < answer.size())
                    {
                        size_t to_send = std::min(static_cast<size_t>(10), answer.size() - sent_bytes);
                        server.send_chunk_data(ctx, answer.data() + sent_bytes, to_send);
                        sent_bytes += to_send;
                    }
                    server.send_chunk_finish(ctx);
                }
            }
            if (info.mPath == "/delayed_answer")
            {
                delayed_thread = std::make_shared<std::thread>([&server, ctx]()
                {
                    // Wait a time
                    std::this_thread::sleep_for(std::chrono::seconds(120));

                    std::unique_lock<std::mutex> l(alive_requests_mutex);
                    if (alive_requests.count(ctx))
                        server.send_html(ctx, "<html><body>Delayed answer arrived</body></html>");
                });
            }

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
