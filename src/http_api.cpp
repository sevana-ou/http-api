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
#include <fstream>

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

std::set<int> request_params::get_int_set(const std::string& name, const std::set<int>& default_value) const
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

    if (result.empty())
        return default_value;

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

std::set<std::string> request_params::get_string_set(const std::string& name, const std::set<std::string>& default_value) const
{
    std::set<std::string> result;
    try
    {
        auto iter_pair = equal_range(name);
        for (auto iter = iter_pair.first; iter != iter_pair.second; iter++)
        {
            std::string t = iter->second;
            if (!result.count(t))
                result.insert(t);
        }
    }
    catch(...)
    {}

    if (result.empty())
        return default_value;

    return result;
}

// ------------- http_server -----------------
void broken_pipe(int /*signum*/)
{
    // Just ignore signal. It is called when pipe (socket connection) is broken and could terminate app.
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
    if (mCurrentFilename.empty())
    {
        // Usual parameter
        mInfo.mParams.insert(std::make_pair(mCurrentName, mCurrentData));
    }
    else
    {
        mInfo.mParams.insert(std::make_pair("content", mCurrentData));
        mInfo.mParams.insert(std::make_pair("filename", mCurrentFilename));
    }
}

typedef enum {Variable, Value, Hex1, Hex2} State;
static void parse_urlencoded_data(request_params& params, const char* buffer_ptr, size_t buffer_len)
{
      State state;
      std::string param_name, param_value;
      char *length, c, hexchar = 0; /* Init'ed to stop -Wall */
      FILE *f = NULL;
      size_t i, len = buffer_len;

      for (state = Variable; len > 0; len--)
      {
        c = *buffer_ptr++;

        switch (state)
        {
        case Variable:				/* Scanning name of var */
            if (c == '=')
            {
                state = Value;
            }
            else
            if (isalnum(c))
                param_name += c;
            break;

        case Value:				/* Scanning a value */
            if (c == ';' || c == '&')
            {
                params.insert(std::make_pair(param_name, param_value));
                state = Variable;
            }
            else
            if (c == '%')
            {
                state = Hex1;
            }
            else
            {
                param_value += (c == '+' ? ' ' : c);
            }
            break;

          case Hex1:				/* 1st char after '%' */
            state = Hex2;
            if ('0' <= c && c <= '9')
                hexchar = c - '0';
            else
            if ('A' <= c && c <= 'F')
                hexchar = c - 'A' + 10;
            else
            if ('a' <= c && c <= 'f')
                hexchar = c - 'a' + 10;
            else
                state = Value;			/* Error, skip char... */
            break;

          case Hex2:				/* 2nd char after '%' */
            if ('0' <= c && c <= '9')
                param_value += char(16 * hexchar + c - '0');
            else
            if ('A' <= c && c <= 'F')
                param_value += char(16 * hexchar + c - 'A' + 10);
            else
            if ('a' <= c && c <= 'f')
                param_value += char(16 * hexchar + c - 'a' + 10);
            else
                ;					/* Error, skip char... */
            state = Value;
            break;

        }
    }
}

// ------------ http_client --------------
http_client::http_client(int timeout_in_seconds)
    :mTimeoutInSeconds(timeout_in_seconds)
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

http_client::ctx http_client::get(const std::string& url, connection_kind kind, response_handler handler)
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
    const char* query = evhttp_uri_get_query(u);

    evhttp_request* r = evhttp_request_new(&process_eof_callback, this);
    r->chunk_cb = &process_data_callback;
    //r->error_cb = &process_error_callback;

    // Add Host: header
    evhttp_add_header(evhttp_request_get_output_headers(r), "Host", addr.first.c_str());
    if (kind == connection_close)
        evhttp_add_header(evhttp_request_get_output_headers(r), "Connection", "Close");

    mRequests[r] = std::pair<response_handler, response_info>(handler, response_info());

    // Run request
    std::string fp = std::string(path ? path : "/") + (query ? std::string("?") + query : std::string());
    int code = evhttp_make_request(c, r, EVHTTP_REQ_GET, fp.c_str());
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
#if defined(TARGET_LINUX)
    pthread_setname_np(pthread_self(), "http_client");
#endif
    while (!mTerminated)
    {
        event_base_dispatch(mIoContext);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
        evhttp_connection_set_timeout(c, mTimeoutInSeconds);

        auto insertResult = mConnections.insert({addr, c});
        connIter = insertResult.first;
    }

    return connIter->second;
}

#if defined(ENABLE_MULTI_THREAD_SERVER)
// ---------------------- http_multi_server ----------------------
#include "evhtp.h"

void http_server::on_http_request(evhtp_request_t* req, void* arg)
{
    if (arg && req)
    {
        http_server* server = reinterpret_cast<http_server*>(arg);
        server->process_request(req);
    }
}

evhtp_res http_server::on_http_request_finalization(evhtp_request_t *req, void *arg)
{
    if (arg && req)
    {
        http_server* server = reinterpret_cast<http_server*>(arg);
        server->process_request_finalization(req);
    }

    return EVHTP_RES_OK;
}

void http_server::on_process_response_queue(evutil_socket_t, short, void *ctx)
{
    http_server* server = reinterpret_cast<http_server*>(ctx);
    if (server)
        server->process_response_queue();
}

static void on_http_error(evhtp_request_t* /*req*/, evhtp_error_flags /*errtype*/, void* /*arg*/)
{

}

http_server::http_server()
{
    signal(SIGPIPE, broken_pipe);

#if defined(TARGET_LINUX) || defined(TARGET_OSX)
    evthread_use_pthreads();
#endif
}

http_server::~http_server()
{
    stop();
}

void http_server::set_port(uint16_t port)
{
    mPort = port;
}

uint16_t http_server::get_port() const
{
    return mPort;
}

void http_server::set_threads(size_t nr)
{
    mNumberOfThreads = nr;
}

size_t http_server::get_threads() const
{
    return mNumberOfThreads;
}

event_base* http_server::get_io_base() const
{
    return mIoContext;
}

static void evhtp_thread_init(evhtp_t * htp, evthr_t * thr, void * arg)
{
#if defined(TARGET_LINUX)
    pthread_setname_np(pthread_self(), "evhtp");
#endif
}

void http_server::start()
{
    mRequestCounter = 0;
    mIoContext = event_base_new();
    mResponseQueueEvent = event_new(mIoContext, -1, 0, &http_server::on_process_response_queue, this);
    mHttpContext = evhtp_new(mIoContext, this);

    // Just to be safe
    if (evhtp_use_callback_locks(mHttpContext) == -1)
    {
        evhtp_free(mHttpContext); mHttpContext = nullptr;
        event_base_free(mIoContext); mIoContext = nullptr;
        return;
    }

    evhtp_enable_flag(mHttpContext, EVHTP_FLAG_ENABLE_ALL);
    auto callback_request_finish = evhtp_set_cb(mHttpContext, "/", &on_http_request, this);
    evhtp_callback_set_hook(callback_request_finish, evhtp_hook_on_request_fini,
                            reinterpret_cast<evhtp_hook>(&on_http_request_finalization), this);

    int rescode = evhtp_bind_socket(mHttpContext, "ipv4:0.0.0.0", mPort, 5);
    if (rescode == -1)
    {
        evhtp_free(mHttpContext); mHttpContext = nullptr;
        event_base_free(mIoContext); mIoContext = nullptr;
        return;
    }

    // Create worker I/O threads
    if (mNumberOfThreads)
        evhtp_use_threads_wexit(mHttpContext, &evhtp_thread_init, nullptr, static_cast<int>(mNumberOfThreads), nullptr);

    // Start listener thread. If nr_of_threads == 0 - it will be acceptor thread too.
    mTerminated = false;
    mWorkerThread = std::make_shared<std::thread>(&http_server::worker, this);
}

void http_server::stop()
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

    event_free(mResponseQueueEvent); mResponseQueueEvent = nullptr;
    event_base_free(mIoContext); mIoContext = nullptr;
}

void http_server::worker()
{
#if defined(TARGET_LINUX)
    pthread_setname_np(pthread_self(), "http_server");
#endif
    while (!mTerminated)
    {
        // event_base_loop(mIoContext, 0);
        try
        {
            event_base_dispatch(mIoContext);
        }
        catch (...)
        {
            std::cerr << "Strange libevent error" << std::endl;
        }
        //std::cout << "event_base_loop exit." << std::endl;
    }
}

void http_server::process_request(evhtp_request *request)
{
    mRequestCounter++;

    // Find context structure
    request_multipart_parser& parser = find_request_parser(request);
    parser.mInfo.mPath = request->uri->path->full ? request->uri->path->full : std::string();

    if (mLoggingHandler)
        mLoggingHandler(*this, "Incoming request to: " + parser.mInfo.mPath);

    // Find headers
    evhtp_kvs* hdr_queue = request->headers_in;
    evhtp_kv* hdr_kv = hdr_queue->tqh_first;
    while (hdr_kv)
    {
        parser.mInfo.mHeaders.insert(std::make_pair(hdr_kv->key, hdr_kv->val ? std::string(hdr_kv->val) : std::string()));
        hdr_kv = hdr_kv->next.tqe_next;
    }

    http_request_ownership ownership = ownership_none;

    if (request->method == htp_method_OPTIONS)
    {
        evhtp_headers_add_header(reinterpret_cast<evhtp_request*>(request)->headers_out,
                                 evhtp_header_new("Access-Control-Allow-Origin", "*", 0, 0));
        evhtp_headers_add_header(reinterpret_cast<evhtp_request*>(request)->headers_out,
                                 evhtp_header_new("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE", 0, 0));
        evhtp_headers_add_header(reinterpret_cast<evhtp_request*>(request)->headers_out,
                                 evhtp_header_new("Access-Control-Max-Age", "86400", 0, 0));
        evhtp_send_reply(request, 204);
    }
    else
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
            mHandler(*this, request, parser.mInfo, ownership);
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
            std::string boundary, content_type;
            if (parser.mInfo.mHeaders.count("Content-Type"))
            {
                auto iter = parser.mInfo.mHeaders.find("Content-Type");
                if (iter != parser.mInfo.mHeaders.end())
                {
                    content_type = iter->second;
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
                    // Do nothing here
                }
            }
            else
            if (content_type.find("urlencoded") != std::string::npos)
            {
                // Maybe there is parameters in request line ?
                evhtp_kvs* param_queue = request->uri->query;
                if (param_queue)
                {
                    evhtp_kv* param = param_queue->tqh_first;
                    while (param)
                    {
                        parser.mInfo.mParams.insert(std::pair<std::string, std::string>(std::string(param->key ? param->key : ""), std::string(param->val ? param->val : "")));
                        param = reinterpret_cast<evhtp_kv*>(param->next.tqe_next);
                    }
                }

                // Special case to handle uploaded .pcap / .pcapng - used in some of our projects. This violates HTTP protocol rules - but this code already in production.
                if (body_size > 4)
                {
                    uint32_t signature = *reinterpret_cast<uint32_t*>(body);
                    bool normal_resolution = signature == 0xa1b2c3d4 || signature == 0xd4c3b2a1;
                    bool ns_resolution = signature == 0xa1b23c4d || signature == 0x4d3cb2a1;
                    bool ng_flag = signature == 0x0A0D0D0A;

                    if (normal_resolution || ns_resolution || ng_flag)
                    {
                        parser.mInfo.mParams.insert(std::make_pair("content", std::string(body, body_size)));
                        parser.mInfo.mParams.insert(std::make_pair("filename", "1.pcap"));
                    }
                    else
                        parse_urlencoded_data(parser.mInfo.mParams, body, body_size);
                }
                else
                    parse_urlencoded_data(parser.mInfo.mParams, body, body_size);
            }
            else
            {
                // TODO: Decode uri from body
            }
            delete[] body; body = nullptr;

            parser.mInfo.mMethod = Method_POST;
            try
            {
                mHandler(*this, request, parser.mInfo, ownership);
            }
            catch(...)
            {}
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

    // Remove used parser instance
    if (ownership == ownership_none)
    {
        auto iter = mRequestContexts.find(request);
        if (iter != mRequestContexts.end())
            mRequestContexts.erase(iter);
    }
    // std::cout << "Request :" << mRequestCounter << std::endl;
}

void http_server::process_request_finalization(evhtp_request_t *request)
{
    try
    {
        {
            std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
            auto iter = mRequestContexts.find(request);
            if (iter != mRequestContexts.end())
                mRequestContexts.erase(iter);
        }

        if (mExpiredHandler)
            mExpiredHandler(*this, request);
    }
    catch(...)
    {}
}

void http_server::process_response_queue()
{
    try
    {
        {
            std::unique_lock<std::mutex> l(mResponseQueueMutex);
            for (auto& item: mResponseQueue)
                item.mCallback(item.mCtx);
            mResponseQueue.clear();
        }
    }
    catch(...)
    {}
}

request_multipart_parser& http_server::find_request_parser(ctx request)
{
    std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
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

void http_server::set_handler(const request_get_handler& handler)
{
    mHandler = handler;
}

void http_server::set_handler(const request_expired_handler& handler)
{
    mExpiredHandler = handler;
}

void http_server::set_handler(const logging_handler &handler)
{
    mLoggingHandler = handler;
}

void http_server::set_content_type(ctx ctx, content_type ct)
{
    if (!ctx)
        return;

    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    const char* ct_text = nullptr;
    switch (ct)
    {
    case content_type_html:         ct_text = "text/html";                  break;
    case content_type_json:         ct_text = "application/json";           break;
    case content_type_js:           ct_text = "text/javascript";            break;
    case content_type_png:          ct_text = "image/png";                  break;
    case content_type_binary:       ct_text = "application/octet-stream";   break;
    }

    // Look for already set Content-Type header
    evhtp_kv_t* ct_header = evhtp_kvs_find_kv(request->headers_out, "Content-Type");
    if (ct_header)
    {
        ct_header->val = const_cast<char*>(ct_text);
        ct_header->v_heaped = 0;
    }
    else
        evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Content-Type", ct_text, 0, 1));
}

void http_server::set_content_type(ctx ctx, const std::string& ct)
{
    if (!ctx)
        return;

    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);

    // Look for already set Content-Type header
    evhtp_kv_t* ct_header = evhtp_kvs_find_kv(request->headers_out, "Content-Type");
    if (ct_header)
    {
        ct_header->val = strdup(ct.c_str());
        ct_header->v_heaped = 1;
    }
    else
        evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Content-Type", ct.c_str(), 0, 1));
}

void http_server::set_cors(ctx ctx)
{
    if (!ctx)
        return;

    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);

    // Look for already set Content-Type header
    evhtp_kv_t* ct_header = evhtp_kvs_find_kv(request->headers_out, "Access-Control-Allow-Origin");
    if (ct_header)
    {
        ct_header->val = const_cast<char*>("*");
        ct_header->v_heaped = 0;
    }
    else
        evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new("Access-Control-Allow-Origin", "*", 0, 0));
}

void http_server::send_json(void* ctx, const std::string& body)
{
    if (!ctx)
        return;

    set_content_type(ctx, content_type_json);
    set_cors(ctx);

    send_chunk_reply(ctx, EVHTP_RES_200);
    send_chunk_data(ctx, body.c_str(), body.size());
    send_chunk_finish(ctx);
}

void http_server::send_html(void* ctx, const std::string& body)
{
    if (!ctx)
        return;

    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    {
        std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
        if (mRequestContexts.find(request) == mRequestContexts.end())
            return;
    }

    set_content_type(ctx, content_type_html);
    send_chunk_reply(ctx, EVHTP_RES_200);
    send_chunk_data(ctx, body.c_str(), body.size());
    send_chunk_finish(ctx);
}


static bool ends_with(const std::string& v, const std::string& suffix)
{
    return v.find(suffix) == v.size() - suffix.length();
}


static http_server::content_type filename_to_ct(const std::string& path)
{
    if (ends_with(path, ".html") || ends_with(path, ".htm"))
        return http_server::content_type_html;
    if (ends_with(path, ".js"))
        return http_server::content_type_js;
    if (ends_with(path, ".json"))
        return http_server::content_type_json;
    if (ends_with(path, ".png"))
        return http_server::content_type_png;

    return http_server::content_type_binary;
}

void http_server::send_file(ctx ctx, const std::string& path)
{
    // Read file content and send
    std::ifstream input_stream(path);
    if (!input_stream.is_open())
    {
        send_error(ctx, 404, "File not found");
        return;
    }

    // Read content
    std::string content((std::istreambuf_iterator<char>(input_stream)),
                         std::istreambuf_iterator<char>());

    set_content_type(ctx, filename_to_ct(path));
    set_cors(ctx);
    send_chunk_reply(ctx, EVHTP_RES_200);
    send_chunk_data(ctx, content.c_str(), content.size());
    send_chunk_finish(ctx);
}

void http_server::send_error(void *ctx, int code, const std::string &/*reason*/)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    {
        std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
        if (mRequestContexts.find(request) == mRequestContexts.end())
            return;
    }

    evhtp_send_reply(reinterpret_cast<evhtp_request*>(ctx), static_cast<evhtp_res>(code));
}

void http_server::send_redirect(ctx ctx, const std::string& uri)
{
    // ToDo
}

void http_server::send_headers(ctx ctx, const response_headers& headers)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    {
        std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
        if (mRequestContexts.find(request) == mRequestContexts.end())
            return;
    }

    for (auto& hdr: headers)
    {
        evhtp_headers_add_header(reinterpret_cast<evhtp_request*>(ctx)->headers_out,
                                 evhtp_header_new(hdr.first.c_str(), hdr.second.c_str(), 1, 1));
    }
}

void http_server::send_chunk_reply(ctx ctx, int code)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    {
        std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
        if (mRequestContexts.find(request) == mRequestContexts.end())
            return;
    }

    evhtp_send_reply_chunk_start(request, static_cast<evhtp_res>(code));
}

void http_server::send_chunk_data(ctx ctx, const void* data, size_t len)
{
    evhtp_request* req = reinterpret_cast<evhtp_request*>(ctx);
    if (!req || !data || !len)
        return;

    // Check if request is alive yet
    {
        std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
        if (mRequestContexts.find(req) == mRequestContexts.end())
            return;
    }

    evbuffer* buf = evbuffer_new();
    evbuffer_add(buf, data, len);
    evhtp_send_reply_chunk(req, buf);
    evbuffer_free(buf);
}

void http_server::send_chunk_finish(ctx ctx)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    if (!request)
        return;

    evhtp_send_reply_chunk_end(request);
}

void http_server::send_content(ctx ctx, const std::string &content)
{
    evhtp_request* request = reinterpret_cast<evhtp_request*>(ctx);
    {
        std::unique_lock<std::recursive_mutex> l(mRequestContextsMutex);
        if (mRequestContexts.find(request) == mRequestContexts.end())
            return;
    }

    evbuffer* buffer = evbuffer_new();
    evbuffer_add(buffer, content.c_str(), content.size());
    evhtp_send_reply_start(request, EVHTP_RES_OK);
    evhtp_send_reply_body(request, buffer);
    evhtp_send_reply_end(request);
}


void http_server::set_keepalive(ctx ctx, bool keepalive)
{
    evhtp_request_set_keepalive(reinterpret_cast<evhtp_request*>(ctx), keepalive ? 1 : 0);
}

void http_server::set_maxbodysize(ctx ctx, size_t size)
{
    evhtp_request_set_max_body_size(reinterpret_cast<evhtp_request*>(ctx), size);
}

size_t http_server::get_number_of_requests() const
{
    return static_cast<size_t>(mRequestCounter.load());
}

/*
    struct queued_response
    {
        ctx mCtx;
        std::function<void(ctx&)> mCallback;
    };
    std::mutex mResponseQueueMutex;
    std::vector<queued_response> mResponseQueue;
    event* mResponseQueueEvent = nullptr;
*/

#define QUEUE_ITEM(X) \
    std::unique_lock<std::mutex> l(mResponseQueueMutex);    \
    mResponseQueue.push_back(qr);                           \
    event_active(mResponseQueueEvent, 0, 0)

void http_server::queue_json(ctx ctx, const std::string& body)
{
    std::string b = body;
    queued_response qr{
        ctx,
        [this, b](http_server::ctx& ctx)
        {
            this->send_json(ctx, b);
        }
    };
    QUEUE_ITEM(qr);
}

void http_server::queue_html(ctx ctx, const std::string& body)
{
    std::string b = body;
    queued_response qr{
        ctx,
        [this, b](http_server::ctx& ctx)
        {
            this->send_html(ctx, b);
        }
    };
    QUEUE_ITEM(qr);
}

void http_server::queue_error(ctx ctx, int code, const std::string& reason)
{
    std::string r = reason;
    queued_response qr{
        ctx,
        [this, code, r](http_server::ctx& ctx)
        {
            this->send_error(ctx, code, r);
        }
    };
    QUEUE_ITEM(qr);

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

timer::timer(event_base* base, std::chrono::milliseconds interval, option flag, callback callback)
    :mCallback(callback)
{
    if (flag == flag_interval_with_immediate)
        callback();

    mTimerEvent = event_new(base, -1, flag != flag_singleshot ? EV_PERSIST : 0,
                            &timer_callback, this);
    timeval tv;
    tv.tv_sec = interval.count() / 1000;
    tv.tv_usec = (interval.count() % 1000) * 1000;

    int retcode = event_add(mTimerEvent, &tv);
    if (retcode == -1)
        std::cerr << "Bad retcode when event_add(): " << std::endl;
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
