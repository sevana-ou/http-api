#include "http_api.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>
#include <event2/thread.h>

#include <signal.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <locale>

#include "multipart_parser.h"
#include "multipart_reader.h"


// --------------- request_params --------------
bool request_params::get_bool(const std::string& name, bool default_value) const
{
    auto iter = find(name);
    if (iter != end())
        return iter->second == "on" || iter->second == "true";
    else
        return default_value;
}

int request_params::get_int(const std::string& name, int default_value) const
{
    try
    {
        auto iter = find(name);
        if (iter != end())
            return std::stoi(iter->second);
        else
            return default_value;
    }
    catch(...)
    {}
    return default_value;
}

std::set<int> request_params::get_int_set(const std::string& name) const
{
    std::set<int> result;
    try
    {
        auto iter = find(name);
        while (iter != end())
        {
            int v = std::stoi(iter->second);
            if (!result.count(v))
                result.insert(v);
            iter++;
        }
    }
    catch(...)
    {}

    return result;
}

std::string request_params::get_string(const std::string& name, const std::string& default_value) const
{
    auto iter = find(name);
    if (iter != end())
        return iter->second;
    else
        return default_value;
}

// ------------- http_server -----------------
void broken_pipe(int /*signum*/)
{
    // Just ignore signal. It is called when pipe (socket connection) is broken and could terminate app.
}

http_server::http_server()
{

}

http_server::~http_server()
{
    stop();
}

void http_server::setPort(uint16_t port)
{
    mPort = port;
}

uint16_t http_server::port() const
{
    return mPort;
}

void http_server::start()
{
    if (mIoContext)
        return;

    mTerminated = false;
    signal(SIGPIPE, broken_pipe);

#if defined(TARGET_LINUX) || defined(TARGET_OSX)
    evthread_use_pthreads();
#endif

    mIoContext = event_base_new();
    mHttpContext = evhttp_new(mIoContext);
    evhttp_bind_socket(mHttpContext, "0.0.0.0", mPort);
    evhttp_set_gencb(mHttpContext, &http_server::process_callback, this);
    evhttp_set_max_body_size(mHttpContext, 20*1024*1024);
    evhttp_set_max_headers_size(mHttpContext, 65536);

    mWorkerThread = std::make_shared<std::thread>(&http_server::worker, this);
    // Thread has no need to be joined - it is controlled via libevent API
    // mWorkerThread->detach();
}

void http_server::stop()
{
    if (!mIoContext)
        return;

    // Exit from worker thread
    mTerminated = true;
    event_base_loopbreak(mIoContext);

    if (mHttpContext)
    {
        evhttp_free(mHttpContext);
        mHttpContext = nullptr;
    }

    if (mWorkerThread)
    {
        if (mWorkerThread->joinable())
            mWorkerThread->join();
        mWorkerThread.reset();
    }
    event_base_free(mIoContext); mIoContext = nullptr;
}

void http_server::set_handler(const request_get_handler& handler)
{
    mHandler = handler;
}

void http_server::send_json(void* ctx, const std::string& body)
{
    if (!ctx)
        return;

    evhttp_request* request = reinterpret_cast<evhttp_request*>(ctx);
    evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json");
    evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Length", std::to_string(body.size()).c_str());

    evbuffer* buffer = evbuffer_new();
    evbuffer_add(buffer, body.c_str(), body.size());
    evhttp_send_reply(request, HTTP_OK, "OK", buffer);
    evbuffer_free(buffer);
}

void http_server::send_html(void* ctx, const std::string& body)
{
    if (!ctx)
        return;

    evhttp_request* request = reinterpret_cast<evhttp_request*>(ctx);
    evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "text/html");
    evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Length", std::to_string(body.size()).c_str());

    evbuffer* buffer = evbuffer_new();
    evbuffer_add(buffer, body.c_str(), body.size());
    evhttp_send_reply(request, HTTP_OK, "OK", buffer);
    evbuffer_free(buffer);
}

void http_server::send_error(void *ctx, int code, const std::string &reason)
{
    if (!ctx)
        return;

    evhttp_send_error(reinterpret_cast<evhttp_request*>(ctx), code, reason.c_str());
}

void http_server::worker()
{
    while (!mTerminated)
    {
        event_base_dispatch(mIoContext);
    }
}

void http_server::process_callback(struct evhttp_request *request, void *arg)
{
    http_server* hs = reinterpret_cast<http_server*>(arg);
    if (hs)
        hs->process_request(request);
}


typedef std::vector<std::pair<std::string, std::string>> temp_params;

void handle_part_begin(MultipartHeaders& headers);
void handle_part_data(const char* buffer, size_t size);
void handle_part_end();

void MimePartBeginCallback(const MultipartHeaders& headers, void *userData)
{
    reinterpret_cast<request_multipart_parser*>(userData)->handle_part_begin(headers);
}

void MimePartDataCallback(const char *buffer, size_t len, void *userData)
{
    reinterpret_cast<request_multipart_parser*>(userData)->handle_part_data(buffer, len);
}

void MimePartEndCallback(void *userData)
{
    reinterpret_cast<request_multipart_parser*>(userData)->handle_part_end();
}

static std::vector<std::string> tokenize(const std::string& s, char c)
{
    auto end = s.cend();
    auto start = end;

    std::vector<std::string> v;
    for( auto it = s.cbegin(); it != end; ++it )
    {
        if( *it != c )
        {
            if( start == end )
                start = it;
            continue;
        }
        if( start != end )
        {
            v.emplace_back(start, it);
            start = end;
        }
    }
    if( start != end )
        v.emplace_back(start, end);
    return v;
}

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

// trim from both ends (copying)
static inline std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

void request_multipart_parser::handle_part_begin(const MultipartHeaders& headers)
{
    for (auto const& item: headers)
    {
        if (item.first == "Content-Disposition")
        {
            // Look for name
            std::vector<std::string> parts = tokenize(item.second, ';');
            for (std::string& s: parts)
            {
                std::vector<std::string> assignment_parts = tokenize(s, '=');
                if (assignment_parts.size() >= 2)
                {
                    // Parameter sent
                    std::string name = trim_copy(assignment_parts.front());
                    std::string value = trim_copy(assignment_parts.back());
                    if (value.size())
                    {
                        if (value.front() == '"' && value.back() == '"')
                            value = value.substr(1, value.size() - 2);
                    }
                    if (name == "filename")
                    {
                        mCurrentFilename = value;
                    }
                    if (name == "name")
                    {
                        mCurrentName = value;
                        mCurrentData.clear();
                        mCurrentFilename.clear();
                    }
                }
            }
        }
    }
}

void request_multipart_parser::handle_part_data(const char* buffer, size_t length)
{
    mCurrentData += std::string(buffer, length);
}

void request_multipart_parser::handle_part_end()
{
    mInfo.mParams.insert(std::make_pair("content", mCurrentData));
    if (mCurrentFilename.size())
        mInfo.mParams.insert(std::make_pair("filename", mCurrentFilename));
}


void http_server::process_request(evhttp_request *request)
{
    // Request
    struct evkeyvalq headers;

    // Parse the query for later lookups
    const char* uri_text = evhttp_request_get_uri(request);
    struct evhttp_uri* uri = evhttp_uri_parse(uri_text);
    evhttp_cmd_type cmd = evhttp_request_get_command(request);

    request_multipart_parser& parser = find_request_parser(request);
    parser.mInfo.mPath = evhttp_uri_get_path(uri);
    parser.mInfo.mHost = evhttp_uri_get_host(uri) ? evhttp_uri_get_host(uri) : std::string();

    // Find headers
    evkeyvalq* hdr_queue = evhttp_request_get_input_headers(request);
    evkeyval* hdr = hdr_queue ? hdr_queue->tqh_first : nullptr;
    while (hdr)
    {
        parser.mInfo.mHeaders.insert(std::make_pair(hdr->key, hdr->value ? std::string(hdr->value) : std::string()));
        hdr = hdr->next.tqe_next;
    }

    if (cmd == EVHTTP_REQ_GET)
    {
        if (mHandler)
        {
            evhttp_parse_query(uri_text, &headers);
            request_params params;
            // Iterate headers and put it do dictionary
            for (evkeyval* val = headers.tqh_first; val != nullptr; val = val->next.tqe_next)
                params.insert(std::pair<std::string, std::string>(std::string(val->key ? val->key : ""), std::string(val->value ? val->value : "")));

            // Call handler
            parser.mInfo.mParams = params;
            parser.mInfo.mMethod = Method_GET;
            mHandler(*this, request, parser.mInfo);
        }
        else
        {
            // Send default answer "not implemented"
            evhttp_send_error(request, HTTP_NOTIMPLEMENTED, "Document not found");
        }
    }
    else
    if (cmd == EVHTTP_REQ_POST)
    {
        if (mHandler)
        {
            std::string boundary;
            if (parser.mInfo.mHeaders.count("Content-Type"))
            {
                auto iter = parser.mInfo.mHeaders.find("Content-Type");
                if (iter != parser.mInfo.mHeaders.end())
                {
                    std::string content_type = iter->second;
                    if (content_type.find("multipart/form-data") != std::string::npos)
                    {
                        std::string::size_type p = content_type.find("boundary=");
                        if (p != std::string::npos)
                            boundary = content_type.substr(p + strlen("boundary="));
                    }
                }
            }
            struct evbuffer* post_buffer = evhttp_request_get_input_buffer(request);
            size_t body_size = evbuffer_get_length(post_buffer);
            char* body = new char[body_size+1];
            evbuffer_remove(post_buffer, body, body_size);
            body[body_size] = 0;

            if (boundary.size())
            {
                parser.mMultipartReader->setBoundary(boundary);
                parser.mMultipartReader->feed(body, body_size);
            }
            else
            {
                // TODO: Decode uri from body
            }
            delete[] body; body = nullptr;

            parser.mInfo.mMethod = Method_POST;
            mHandler(*this, request, parser.mInfo);

            // Remove used parser instance
            auto iter = mRequestContexts.find(request);
            if (iter != mRequestContexts.end())
                mRequestContexts.erase(iter);
        }
        else
        {
            evhttp_send_error(request, HTTP_NOTIMPLEMENTED, "Not implemented");
        }
    }
    else
    {
        // Send default answer
        evhttp_send_error(request, HTTP_BADMETHOD, "Method not allowed.");
    }
    evhttp_uri_free(uri);
}

request_multipart_parser& http_server::find_request_parser(ctx request)
{
    std::shared_ptr<request_multipart_parser> result;

    auto iter = mRequestContexts.find(request);
    if (iter == mRequestContexts.end())
    {
        result = std::make_shared<request_multipart_parser>();
        result->mMultipartReader = std::make_shared<MultipartReader>();

        result->mMultipartReader->onPartBegin = &MimePartBeginCallback;
        result->mMultipartReader->onPartEnd = &MimePartEndCallback;
        result->mMultipartReader->onPartData = &MimePartDataCallback;
        result->mMultipartReader->userData = result.get();

        mRequestContexts.insert(std::make_pair(request, result));
        return *result;
    }
    else
        return *iter->second;
}


// ------------ http_client --------------
http_client::http_client()
{
#if defined(TARGET_LINUX) || defined(TARGET_OSX)
    //evthread_use_pthreads();
#endif
    signal(SIGPIPE, broken_pipe);

    mTerminated = false;
    mIoContext = event_base_new();
    if (mIoContext)
        mWorkerThread = std::make_shared<std::thread>(&http_client::worker, this);
}

http_client::~http_client()
{
    mTerminated = true;
    if (mIoContext)
        event_base_loopbreak(mIoContext);
    if (mWorkerThread)
    {
        if (mWorkerThread->joinable())
        {
            mWorkerThread->join();
        }
        mWorkerThread.reset();
    }

    // Free all connections
    for (auto& connIter: mConnections)
        evhttp_connection_free(connIter.second);

    if (mIoContext)
        event_base_free(mIoContext);
}

http_client::ctx http_client::get(const std::string& url, response_handler handler)
{
    evhttp_uri* u = evhttp_uri_parse(url.c_str());
    if (!u)
        return nullptr;

    // Find address of host
    int port = evhttp_uri_get_port(u);
    const char* scheme = evhttp_uri_get_scheme(u);
    if (port == -1)
    {
        if (strstr(scheme, "https"))
            port = 443;
        else
            port = 80;
    }

    std::pair<std::string, uint16_t> addr = {std::string(evhttp_uri_get_host(u)), static_cast<uint16_t>(port) };
    evhttp_connection* c = find_connection(addr);

    if (!c)
    {
        evhttp_uri_free(u);
        return nullptr;
    }

    const char* path = evhttp_uri_get_path(u);

    evhttp_request* r = evhttp_request_new(&process_eof_callback, this);
    r->chunk_cb = &process_data_callback;
    //r->error_cb = &process_error_callback;

    // Add Host: header
    evhttp_add_header(evhttp_request_get_output_headers(r), "Host", addr.first.c_str());
    evhttp_add_header(evhttp_request_get_output_headers(r), "Connection", "Close");

    mRequests[r] = std::pair<response_handler, response_info>(handler, response_info());

    // Run request
    int code = evhttp_make_request(c, r, EVHTTP_REQ_GET, path ? path : "/");
    evhttp_uri_free(u); u = nullptr;

    if (code)
        return nullptr;

    return r;
}

event_base* http_client::getIoContext()
{
    return mIoContext;
}

void http_client::worker()
{
    while (!mTerminated)
    {
        event_base_dispatch(mIoContext);
    }
}

void http_client::process_data_callback(struct evhttp_request *request, void *tag)
{
    http_client* hc = reinterpret_cast<http_client*>(tag);
    if (hc)
        hc->process_request_data(request);
    else
    {
        // Shit happens
    }
}

void http_client::process_eof_callback(struct evhttp_request* request, void* tag)
{
    http_client* hc = reinterpret_cast<http_client*>(tag);
    if (hc)
        hc->process_request_eof(request);
}

void http_client::process_error_callback(int /*err*/, void* /*tag*/)
{
    // Do nothing here - it is not clear how to handle this code
}

void http_client::process_request_data(evhttp_request* request)
{
    std::unique_lock<std::mutex> l(mMutex);
    auto iter = mRequests.find(request);
    if (iter == mRequests.end())
        return;

    auto& v = iter->second;
    if (v.first)
    {
        v.second.mCode = evhttp_request_get_response_code(request);
        v.second.mChunk.clear();
        v.second.mChunk.resize(evbuffer_get_length(request->input_buffer));
        evbuffer_remove(request->input_buffer, const_cast<char*>(v.second.mChunk.data()), v.second.mChunk.size());
        v.second.mAllData += v.second.mChunk;
        try
        {
            v.first(*this, request, v.second);
        }
        catch(...)
        {}
    }
    else
    {
        // Clear buffer
        evbuffer_drain(request->input_buffer, evbuffer_get_length(request->input_buffer));
    }
}

void http_client::process_request_eof(evhttp_request *request)
{
    std::unique_lock<std::mutex> l(mMutex);
    auto iter = mRequests.find(request);
    if (iter == mRequests.end())
        return;

    auto& v = iter->second;
    if (v.first)
    {
        v.second.mChunk.clear();
        try
        {
            v.first(*this, request, v.second);
        }
        catch(...)
        {}
    }
    mRequests.erase(iter);
}

void http_client::process_request_error(evhttp_request* request, int err)
{
    std::unique_lock<std::mutex> l(mMutex);
    auto iter = mRequests.find(request);
    if (iter == mRequests.end())
        return;

    auto& v = iter->second;
    if (v.first)
    {
        v.second.mCode = err;
        v.second.mChunk.clear();
        try
        {
            v.first(*this, request, v.second);
        }
        catch(...)
        {}
    }
    mRequests.erase(iter);
}

evhttp_connection* http_client::find_connection(const std::pair<std::string, uint16_t>& addr)
{
    std::unique_lock<std::mutex> l(mMutex);

    auto connIter = mConnections.find(addr);
    if (connIter == mConnections.end())
    {
        evhttp_connection* c = evhttp_connection_base_new(mIoContext, nullptr, addr.first.c_str(), addr.second);
        auto insertResult = mConnections.insert({addr, c});
        connIter = insertResult.first;
    }

    return connIter->second;
}

#if defined(ENABLE_MULTI_THREAD_SERVER)
// ---------------------- http_multi_server ----------------------
#include "evhtp.h"

void http_server_multi::on_http_request(evhtp_request_t* req, void* arg)
{
    if (arg && req)
    {
        http_server_multi* server = reinterpret_cast<http_server_multi*>(arg);
        server->process_request(req);
    }
}

evhtp_res http_server_multi::on_http_request_finalization(evhtp_request_t *req, void *arg)
{
    if (arg && req)
    {
        http_server_multi* server = reinterpret_cast<http_server_multi*>(arg);
        server->process_request_finalization(req);
    }

    return EVHTP_RES_OK;
}

static void on_http_error(evhtp_request_t* req, evhtp_error_flags errtype, void* arg)
{

}

http_server_multi::http_server_multi()
{
    signal(SIGPIPE, broken_pipe);

#if defined(TARGET_LINUX) || defined(TARGET_OSX)
    evthread_use_pthreads();
#endif
}

http_server_multi::~http_server_multi()
{
    stop();
}

void http_server_multi::setPort(uint16_t port)
{
    mPort = port;
}

uint16_t http_server_multi::port() const
{
    return mPort;
}

void http_server_multi::setNrOfThreads(size_t nr)
{
    mNumberOfThreads = nr;
}

size_t http_server_multi::nrOfThreads() const
{
    return mNumberOfThreads;
}

void http_server_multi::start()
{
    mIoContext = event_base_new();
    mHttpContext = evhtp_new(mIoContext, this);

    // Just to be safe
    evhtp_use_callback_locks(mHttpContext);

    evhtp_enable_flag(mHttpContext, EVHTP_FLAG_ENABLE_ALL);
    auto callback = evhtp_set_cb(mHttpContext, "/", &on_http_request, this);
    evhtp_callback_set_hook(callback, evhtp_hook_on_request_fini,
                            reinterpret_cast<evhtp_hook>(&on_http_request_finalization), this);

    int rescode = evhtp_bind_socket(mHttpContext, "ipv4:0.0.0.0", mPort, 5);
    size_t nr_of_threads = mNumberOfThreads ? mNumberOfThreads : std::thread::hardware_concurrency();
    if (!nr_of_threads)
        nr_of_threads = 1;

    evhtp_use_threads_wexit(mHttpContext, nullptr, nullptr, static_cast<int>(nr_of_threads), nullptr);

    // Start worker listener thread
    mTerminated = false;
    mWorkerThread = std::make_shared<std::thread>(&http_server_multi::worker, this);
}

void http_server_multi::stop()
{
    if (!mIoContext)
        return;


    if (mHttpContext)
    {
        evhtp_unbind_socket(mHttpContext);
        evhtp_free(mHttpContext);
        mHttpContext = nullptr;
    }

    mTerminated = true;
    event_base_loopbreak(mIoContext);

    if (mWorkerThread)
    {
        if (mWorkerThread->joinable())
            mWorkerThread->join();
        mWorkerThread.reset();
    }

    event_base_free(mIoContext); mIoContext = nullptr;
}

void http_server_multi::worker()
{
    while (!mTerminated)
    {
        event_base_loop(mIoContext, 0);
        //std::cout << "event_base_loop exit." << std::endl;
    }
}


void http_server_multi::process_request(evhtp_request *request)
{
    // Find context structure
    request_multipart_parser& parser = find_request_parser(request);
    parser.mInfo.mPath = request->uri->path->full ? request->uri->path->full : std::string();

    // Find headers
    evhtp_kvs* hdr_queue = request->headers_in;
    evhtp_kv* hdr_kv = hdr_queue->tqh_first;
    while (hdr_kv)
    {
        parser.mInfo.mHeaders.insert(std::make_pair(hdr_kv->key, hdr_kv->val ? std::string(hdr_kv->val) : std::string()));
        hdr_kv = hdr_kv->next.tqe_next;
    }

    if (request->method == htp_method_GET)
    {
        if (mHandler)
        {
            request_params params;

            evhtp_kvs* param_queue = request->uri->query;
            if (param_queue)
            {
                evhtp_kv* param = param_queue->tqh_first;
                while (param)
                {
                    params.insert(std::pair<std::string, std::string>(std::string(param->key ? param->key : ""), std::string(param->val ? param->val : "")));
                    param = reinterpret_cast<evhtp_kv*>(param->next.tqe_next);
                }
            }

            // Call handler
            parser.mInfo.mParams = params;
            parser.mInfo.mMethod = Method_GET;
            mHandler(*this, request, parser.mInfo);
        }
        else
        {
            // Send default answer "not implemented"
            evhtp_send_reply(request, EVHTP_RES_NOTIMPL);
        }
    }
    else
    if (request->method == htp_method_POST)
    {
        if (mHandler)
        {
            std::string boundary;
            if (parser.mInfo.mHeaders.count("Content-Type"))
            {
                auto iter = parser.mInfo.mHeaders.find("Content-Type");
                if (iter != parser.mInfo.mHeaders.end())
                {
                    std::string content_type = iter->second;
                    if (content_type.find("multipart/form-data") != std::string::npos)
                    {
                        std::string::size_type p = content_type.find("boundary=");
                        if (p != std::string::npos)
                            boundary = content_type.substr(p + strlen("boundary="));
                    }
                }
            }
            evbuffer* post_buffer = request->buffer_in;
            size_t body_size = evbuffer_get_length(post_buffer);
            char* body = new char[body_size+1];
            evbuffer_remove(post_buffer, body, body_size);
            body[body_size] = 0;

            if (boundary.size())
            {
                parser.mMultipartReader->setBoundary(boundary);
                parser.mMultipartReader->feed(body, body_size);
                if (parser.mMultipartReader->succeeded())
                {
                    ;
                }
            }
            else
            {
                // TODO: Decode uri from body
            }
            delete[] body; body = nullptr;

            parser.mInfo.mMethod = Method_POST;
            mHandler(*this, request, parser.mInfo);

            // Remove used parser instance
            auto iter = mRequestContexts.find(request);
            if (iter != mRequestContexts.end())
                mRequestContexts.erase(iter);
        }
        else
        {
            evhtp_send_reply(request, EVHTP_RES_NOTIMPL);
        }
    }
    else
    {
        // Send default answer
        evhtp_send_reply(request, EVHTP_RES_NOTIMPL);
    }
}

void http_server_multi::process_request_finalization(evhtp_request_t *request)
{
    try
    {
        if (mExpiredHandler)
            mExpiredHandler(*this, request);
    }
    catch(...)
    {}
}

request_multipart_parser& http_server_multi::find_request_parser(ctx request)
{
    std::shared_ptr<request_multipart_parser> result;

    auto iter = mRequestContexts.find(request);
    if (iter == mRequestContexts.end())
    {
        result = std::make_shared<request_multipart_parser>();
        result->mMultipartReader = std::make_shared<MultipartReader>();

        result->mMultipartReader->onPartBegin = &MimePartBeginCallback;
        result->mMultipartReader->onPartEnd = &MimePartEndCallback;
        result->mMultipartReader->onPartData = &MimePartDataCallback;
        result->mMultipartReader->userData = result.get();

        mRequestContexts.insert(std::make_pair(request, result));
        return *result;
    }
    else
        return *iter->second;
}

void http_server_multi::set_handler(const request_get_handler& handler)
{
    mHandler = handler;
}

void http_server_multi::set_handler(const request_expired_handler& handler)
{
    mExpiredHandler = handler;
}

void http_server_multi::send_json(void* ctx, const std::string& body)
{
    if (!ctx)
        return;

    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Content-Type", "application/json", 0, 0));
    evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Content-Length", std::to_string(body.size()).c_str(), 0, 1));

    evbuffer* buffer = evbuffer_new();
    evbuffer_add(buffer, body.c_str(), body.size());

    evhtp_send_reply_start(request, EVHTP_RES_OK);
    evhtp_send_reply_body(request, buffer);
    evhtp_send_reply_end(request);

    evbuffer_free(buffer);
}

void http_server_multi::send_html(void* ctx, const std::string& body)
{
    if (!ctx)
        return;

    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);

    // Send headers
    evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Content-Type", "text/html", 0, 0));
    evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Content-Length", std::to_string(body.size()).c_str(), 0, 1));

    evbuffer* buffer = evbuffer_new();
    evbuffer_add(buffer, body.c_str(), body.size());

    evhtp_send_reply_start(request, EVHTP_RES_OK);
    evhtp_send_reply_body(request, buffer);
    evhtp_send_reply_end(request);
    evbuffer_free(buffer);
}

void http_server_multi::send_error(void *ctx, int code, const std::string &/*reason*/)
{
    if (!ctx)
        return;
    evhtp_send_reply(reinterpret_cast<evhtp_request*>(ctx), static_cast<evhtp_res>(code));
}

void http_server_multi::send_redirect(ctx ctx, const std::string& uri)
{
    // ToDo
}

void http_server_multi::send_headers(ctx ctx, const response_headers& headers)
{
    for (auto& hdr: headers)
    {
        evhtp_headers_add_header(reinterpret_cast<evhtp_request*>(ctx)->headers_out,
                                 evhtp_header_new(hdr.first.c_str(), hdr.second.c_str(), 1, 1));
    }
}

void http_server_multi::send_chunk_reply(ctx ctx, int code)
{
    evhtp_send_reply_chunk_start(reinterpret_cast<evhtp_request*>(ctx), code);
}

void http_server_multi::send_chunk_data(ctx ctx, const void* data, size_t len)
{
    evhtp_request* req = reinterpret_cast<evhtp_request*>(ctx);
    if (!req || !data || !len)
        return;

    evbuffer* buf = evbuffer_new();
    evbuffer_add(buf, data, len);
    evhtp_send_reply_chunk(req, buf);
    evbuffer_free(buf);
}

void http_server_multi::send_chunk_finish(ctx ctx)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    if (!request)
        return;
    evhtp_send_reply_chunk_end(request);
}

void http_server_multi::send_content(ctx ctx, const std::string &content)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);

    evbuffer* buffer = evbuffer_new();
    evbuffer_add(buffer, content.c_str(), content.size());
    evhtp_send_reply_start(request, EVHTP_RES_OK);
    evhtp_send_reply_body(request, buffer);
    evhtp_send_reply_end(request);
}
#endif


// ----------------- timer ---------------------
static void timer_callback(evutil_socket_t, short, void* arg)
{
    try
    {
        timer* t = reinterpret_cast<timer*>(arg);
        t->get_callback()();
    }
    catch(...)
    {}
}

timer::timer(event_base* base, std::chrono::milliseconds interval, int flag, callback callback)
    :mCallback(callback)
{
    if (flag == flag_interval_with_immediate)
        callback();

    mTimerEvent = event_new(base, -1, flag != flag_singleshot ? EV_PERSIST : 0,
                            &timer_callback, this);
    timeval tv;
    tv.tv_sec = interval.count() / 1000;
    tv.tv_usec = (interval.count() % 1000) * 1000;

    event_add(mTimerEvent, &tv);
}

timer::~timer()
{
    if (mTimerEvent)
    {
        event_del(mTimerEvent);
        event_free(mTimerEvent);
        mTimerEvent = nullptr;
    }
}

timer::callback timer::get_callback()
{
    return mCallback;
}
