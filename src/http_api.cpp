#include "http_api.h"
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>
#include <event2/thread.h>

#include <signal.h>
#include <string.h>
#include <iostream>

void broken_pipe(int signum)
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
    mGetHandler = handler;
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

void http_server::process_request(evhttp_request *request)
{
    // Request
    struct evkeyvalq headers;

    // Parse the query for later lookups
    const char* uri_text = evhttp_request_get_uri(request);
    struct evhttp_uri* uri = evhttp_uri_parse(uri_text);
    evhttp_cmd_type cmd = evhttp_request_get_command(request);
    request_info ri;
    ri.mPath = evhttp_uri_get_path(uri);
    ri.mHost = evhttp_uri_get_host(uri) ? evhttp_uri_get_host(uri) : std::string();

    if (cmd == EVHTTP_REQ_GET)
    {
        if (mGetHandler)
        {
            evhttp_parse_query(uri_text, &headers);
            request_params params;
            // Iterate headers and put it do dictionary
            for (evkeyval* val = headers.tqh_first; val != nullptr; val = val->next.tqe_next)
                params.insert(std::pair<std::string, std::string>(std::string(val->key ? val->key : ""), std::string(val->value ? val->value : "")));

            // Call handler
            mGetHandler(*this, request, ri, params);
        }
        else
        {
            // Send default answer 404 not found
            evhttp_send_error(request, HTTP_NOTFOUND, "Document not found");
        }
    }
    else
    {
        // Send default answer
        evhttp_send_error(request, HTTP_BADMETHOD, "Method not allowed.");
    }
    evhttp_uri_free(uri);
}

// ------------ http_client --------------
http_client::http_client()
{
#if defined(TARGET_LINUX) || defined(TARGET_OSX)
    evthread_use_pthreads();
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
    r->error_cb = &process_error_callback;

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

void http_client::process_error_callback(evhttp_request_error /*err*/, void* /*tag*/)
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

void http_client::process_request_error(evhttp_request* request, evhttp_request_error err)
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
