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
#include <vector>

struct evhttp_request;
struct evhttp;
struct event_base;
struct evhttp_connection;
class MultipartReader;
class MultipartHeaders;

enum http_method
{
    Method_GET,
    Method_POST
};


// Request parameters & info
typedef std::multimap<std::string, std::string> request_params;
typedef std::multimap<std::string, std::string> request_headers;

struct request_info
{
    std::string mHost, mPath;
    http_method mMethod;
    request_headers mHeaders;
    request_params mParams;
};

struct request_multipart_parser
{
    request_info mInfo;
    std::shared_ptr<MultipartReader> mMultipartReader;

    std::string mCurrentName, mCurrentFilename, mCurrentData;

    void handle_part_begin(const MultipartHeaders& headers);
    void handle_part_data(const char* buffer, size_t size);
    void handle_part_end();
};

class http_server
{
public:
    http_server();
    ~http_server();

    void setPort(uint16_t port);
    uint16_t port() const;

    void start();
    void stop();

    // Request context
    typedef void* ctx;

    // Parsed information about requests
    std::map<ctx, std::shared_ptr<request_multipart_parser>> mRequestContexts;

    // Callback to receive requests
    typedef std::function<void(http_server& server, ctx ctx, const request_info& ri)> request_get_handler;

    void set_handler(const request_get_handler& handler);
    void send_json(ctx ctx, const std::string& body);
    void send_html(ctx ctx, const std::string& body);
    void send_error(ctx ctx, int code, const std::string& reason = "");

private:
    uint16_t mPort = 8080;
    evhttp* mHttpContext = nullptr;
    event_base* mIoContext = nullptr;
    std::shared_ptr<std::thread> mWorkerThread;
    request_get_handler mHandler;
    std::atomic_bool mTerminated;

    void worker();
    static void process_callback(struct evhttp_request *request, void *arg);
    void process_request(evhttp_request* request);
    request_multipart_parser& find_request_parser(ctx request);
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

    typedef std::function<void(http_client& client, ctx ctx, response_info& ri)> response_handler;
    ctx get(const std::string& url, response_handler handler);

private:
    event_base* mIoContext = nullptr;
    evhttp_connection* mConn = nullptr;
    std::map<std::pair<std::string, uint16_t>, evhttp_connection*> mConnections;
    std::map<evhttp_request*, std::pair<response_handler, response_info>> mRequests;
    std::shared_ptr<std::thread> mWorkerThread;
    std::mutex mMutex;
    std::atomic_bool mTerminated;

    void worker();
    static void process_data_callback(evhttp_request* request, void* tag);
    static void process_eof_callback(evhttp_request* request, void* tag);
    static void process_error_callback(int err, void* tag);

    void process_request_data(evhttp_request* request);
    void process_request_eof(evhttp_request* request);
    void process_request_error(evhttp_request* request, int err);

    evhttp_connection* find_connection(const std::pair<std::string, uint16_t>& addr);
    std::pair<response_handler, response_info>* find_request(evhttp_request* request);
};

#if defined(ENABLE_MULTI_THREAD_SERVER)
#include <evhtp/evhtp.h>

class http_server_multi
{
public:
    http_server_multi();
    ~http_server_multi();

    void setPort(uint16_t port);
    uint16_t port() const;

    void setNrOfThreads(size_t nr);
    size_t nrOfThreads() const;

    void start();
    void stop();

    // Request context
    typedef void* ctx;

    // Parsed information about requests
    std::map<ctx, std::shared_ptr<request_multipart_parser>> mRequestContexts;

    // Callback to receive requests
    typedef std::function<void(http_server_multi& server, ctx ctx, const request_info& ri)> request_get_handler;

    void set_handler(const request_get_handler& handler);
    void send_json(ctx ctx, const std::string& body);
    void send_html(ctx ctx, const std::string& body);
    void send_error(ctx ctx, int code, const std::string& reason = "");

private:
    uint16_t mPort = 8080;
    event_base* mIoContext = nullptr;
    std::shared_ptr<std::thread> mWorkerThread;
    request_get_handler mHandler;
    std::atomic_bool mTerminated;
    evhtp* mHttpContext = nullptr;
    size_t mNumberOfThreads = 0;

    void worker();
    static void on_http_request(evhtp_request_t* req, void* arg);
    void process_request(evhtp_request_t* request);
    request_multipart_parser& find_request_parser(ctx request);
};
#endif

#endif
