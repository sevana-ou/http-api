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
#include <set>

struct event;
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
class request_params: public std::multimap<std::string, std::string>
{
public:
    bool            get_bool(const std::string& name, bool default_value = false) const;
    int             get_int(const std::string& name, int default_value = 0) const;
    std::set<int>   get_int_set(const std::string& name) const;
    std::string     get_string(const std::string& name, const std::string& default_value = std::string()) const;
};

typedef std::multimap<std::string, std::string> request_headers;
typedef std::multimap<std::string, std::string> response_headers;

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

class http_client
{
public:
    http_client(int timeout_in_seconds = 60);
    ~http_client();

    struct response_info
    {
        int mCode;
        std::string mAllData, mChunk;
    };

    typedef void* ctx;

    typedef std::function<void(http_client& client, ctx ctx, response_info& ri)> response_handler;
    enum connection_kind
    {
        connection_close,
        connection_keepalive
    };

    ctx get(const std::string& url, connection_kind kind, response_handler handler);

    event_base* getIoContext();
private:
    event_base* mIoContext = nullptr;
    evhttp_connection* mConn = nullptr;
    std::map<std::pair<std::string, uint16_t>, evhttp_connection*> mConnections;
    std::map<evhttp_request*, std::pair<response_handler, response_info>> mRequests;
    std::shared_ptr<std::thread> mWorkerThread;
    std::mutex mMutex;
    std::atomic_bool mTerminated;
    int mTimeoutInSeconds = 0;

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

class http_server
{
public:
    http_server();
    ~http_server();

    void setPort(uint16_t port);
    uint16_t port() const;

    void setNrOfThreads(size_t nr);
    size_t nrOfThreads() const;

    void start();
    void stop();

    // Request context
    typedef void* ctx;

    // Parsed information about requests
    std::recursive_mutex mRequestContextsMutex;
    std::map<ctx, std::shared_ptr<request_multipart_parser>> mRequestContexts;

    enum context_ownership
    {
        context_retain,
        context_finish
    };

    // Callback to receive requests
    typedef std::function<context_ownership(http_server& server, ctx ctx, const request_info& ri)> request_get_handler;

    // Callback to receive notification about expired request
    typedef std::function<void(http_server& server, ctx ctx)> request_expired_handler;

    void set_handler(const request_get_handler& handler);
    void set_handler(const request_expired_handler& handler);

    enum content_type
    {
        content_type_html,
        content_type_json
    };

    void set_content_type(ctx ctx, content_type ct);
    void set_content_type(ctx ctx, const std::string& ct);

    // One-liners to send JSON/HTML and close connection (most probably)
    void send_json(ctx ctx, const std::string& body);
    void send_html(ctx ctx, const std::string& body);

    void send_error(ctx ctx, int code, const std::string& reason = "");

    void send_redirect(ctx ctx, const std::string& uri);
    void send_headers(ctx ctx, const response_headers& headers);

    // No headers is sent in this method. Please use send_headers before
    void send_content(ctx ctx, const std::string& content);

    // No headers is sent in this method. Please use send_headers before
    void send_chunk_reply(ctx ctx, int code);
    void send_chunk_data(ctx ctx, const void* data, size_t len);
    void send_chunk_finish(ctx ctx);

    void set_keepalive(ctx ctx, bool keepalive);
    void set_maxbodysize(ctx ctx, size_t size);

private:
    uint16_t mPort = 8080;
    event_base* mIoContext = nullptr;
    std::shared_ptr<std::thread> mWorkerThread;
    request_get_handler mHandler;
    request_expired_handler mExpiredHandler;

    std::atomic_bool mTerminated;
    evhtp* mHttpContext = nullptr;
    size_t mNumberOfThreads = 0;

    void worker();
    static void on_http_request(evhtp_request_t* req, void* arg);
    static evhtp_res on_http_request_finalization(evhtp_request_t* req, void* arg);

    void process_request(evhtp_request_t* request);
    void process_request_finalization(evhtp_request_t* request);

    request_multipart_parser& find_request_parser(ctx request);
};
#endif

class timer
{
public:
    typedef std::function<void()> callback;
    enum
    {
        flag_singleshot,
        flag_interval,
        flag_interval_with_immediate
    };

    timer(event_base* base, std::chrono::milliseconds interval, int flag, callback callback);
    ~timer();
    callback get_callback();

protected:
    event* mTimerEvent = nullptr;
    callback mCallback;
};

#endif
