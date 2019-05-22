#ifndef __HTTP_API_H
#define __HTTP_API_H

#include <string>
#include <stdint.h>
#include <functional>
#include <memory>
#include <thread>
#include <map>
#include <mutex>
#include <atomic>

#include <event2/event.h>
#include <event2/http.h>

class http_server
{
public:
    http_server();
    ~http_server();

    void setPort(uint16_t port);
    uint16_t port() const;

    void start();
    void stop();

    typedef std::multimap<std::string, std::string> request_params;
    struct request_info
    {
        std::string mHost, mPath;
    };

    typedef std::function<void(http_server& server, void* ctx, const request_info& ri, const request_params& params)> request_get_handler;

    void set_handler(const request_get_handler& handler);
    void send_json(void* ctx, const std::string& body);
    void send_html(void* ctx, const std::string& body);
    void send_error(void* ctx, int code, const std::string& reason = "");

private:
    uint16_t mPort = 8080;
    evhttp* mHttpContext = nullptr;
    event_base* mIoContext = nullptr;
    std::shared_ptr<std::thread> mWorkerThread;
    request_get_handler mGetHandler;
    std::atomic_bool mTerminated;

    void worker();
    static void process_callback(struct evhttp_request *request, void *arg);
    void process_request(evhttp_request* request);
};

class http_client
{
public:
    http_client();
    ~http_client();

    struct response_info
    {
        int mCode;
        std::string mAllData, mChunk;
    };

    typedef void* ctx;

    typedef std::function<void(http_client& client, void* ctx, const response_info& ri)> response_handler;
    ctx get(const std::string& url, response_handler handler);

private:
    event_base* mIoContext = nullptr;
    evhttp_connection* mConn = nullptr;
    std::map<std::pair<std::string, uint16_t>, evhttp_connection*> mConnections;
    std::map<evhttp_request*, std::pair<response_handler, response_info>> mRequests;
    std::shared_ptr<std::thread> mWorkerThread;
    std::mutex mMutex;

    void worker();
    static void process_data_callback(evhttp_request* request, void* tag);
    static void process_eof_callback(evhttp_request* request, void* tag);
    static void process_error_callback(evhttp_request_error err, void* tag);

    void process_request_data(evhttp_request* request);
    void process_request_eof(evhttp_request* request);
    void process_request_error(evhttp_request* request, evhttp_request_error err);

    evhttp_connection* find_connection(const std::pair<std::string, uint16_t>& addr);
    std::pair<response_handler, response_info>* find_request(evhttp_request* request);
};

#endif
