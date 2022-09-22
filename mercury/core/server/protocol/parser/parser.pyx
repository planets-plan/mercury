#cython: language_level=3
import asyncio

from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_SIMPLE, Py_buffer

from .error import  (
    HttpParserError,
    HttpParserCallbackError,
    HttpParserInvalidStatusError,
    HttpParserInvalidMethodError,
    HttpParserInvalidURLError,
    HttpParserUpgrade
)

cimport cython
from . cimport cparser
from .python cimport PyMemoryView_Check, PyMemoryView_GET_BUFFER


__all__ = ["HttpRequestParser"]

@cython.internal
cdef class HttpParser:

    cdef:
        cparser.llhttp_t* _cparser
        cparser.llhttp_settings_t* _csettings

        bytes _current_header_name
        bytes _current_header_value

        _proto_on_url, _proto_on_status, _proto_on_body, \
        _proto_on_header, _proto_on_headers_complete, \
        _proto_on_message_complete, _proto_on_chunk_header, \
        _proto_on_chunk_complete, _proto_on_message_begin

        object _last_error

        Py_buffer py_buf

    def __cinit__(self):
        self._cparser = <cparser.llhttp_t*> PyMem_Malloc(sizeof(cparser.llhttp_t))
        if self._cparser is NULL:
            raise MemoryError()

        self._csettings = <cparser.llhttp_settings_t*> PyMem_Malloc(sizeof(cparser.llhttp_settings_t))
        if self._csettings is NULL:
            raise MemoryError()

    def __dealloc__(self):
        PyMem_Free(self._cparser)
        PyMem_Free(self._csettings)

    cdef _init(self, protocol, cparser.llhttp_type_t mode):
        cparser.llhttp_settings_init(self._csettings)
        cparser.llhttp_init(self._cparser, mode, self._csettings)

        self._cparser.data = <void*>self
        self._current_header_name = None
        self._current_header_value = None

        # on_header
        self._proto_on_header = getattr(protocol, "on_header", None)
        if self._proto_on_header is not None:
            self._csettings.on_header_field = cb_on_header_field
            self._csettings.on_header_value = cb_on_header_value

        # on_headers_complete
        self._proto_on_headers_complete = getattr(protocol, "on_headers_complete", None)
        self._csettings.on_headers_complete = cb_on_headers_complete

        # on_body
        self._proto_on_body = getattr(protocol, "on_body", None)
        if self._proto_on_body is not None:
            self._csettings.on_body = cb_on_body

        # on_message_begin: Invoked when a new request/response starts.
        self._proto_on_message_begin = getattr(protocol, "on_message_begin", None)
        if self._proto_on_message_begin is not None:
            self._csettings.on_message_begin = cb_on_message_begin

        # on_message_complete
        self._proto_on_message_complete = getattr(protocol, "on_message_complete", None)
        if self._proto_on_message_complete is not None:
            self._csettings.on_message_complete = cb_on_message_complete

        # on_chunk_header
        self._proto_on_chunk_header = getattr(protocol, 'on_chunk_header', None)
        self._csettings.on_chunk_header = cb_on_chunk_header

        # on_chunk_complete
        self._proto_on_chunk_complete = getattr(protocol, 'on_chunk_complete', None)
        self._csettings.on_chunk_complete = cb_on_chunk_complete

        self._last_error = None

    cdef _maybe_call_on_header(self):
        if self._current_header_value is not None:
            current_header_name = self._current_header_name
            current_header_value = self._current_header_value

            self._current_header_name = self._current_header_value = None

            if self._proto_on_header is not None:
                self._proto_on_header(current_header_name, current_header_value)

    cdef _on_header_field(self, bytes field):
        self._maybe_call_on_header()

        if self._current_header_name is None:
            self._current_header_name = field
        else:
            self._current_header_name += field

    cdef _on_header_value(self, bytes val):
        if self._current_header_value is None:
            self._current_header_value = val
        else:
            self._current_header_value += val

    cdef _on_headers_complete(self):
        self._maybe_call_on_header()

        if self._proto_on_headers_complete is not None:
            self._proto_on_headers_complete()

    cdef _on_chunk_header(self):
        if self._current_header_value is not None or self._current_header_name is not None:
            raise HttpParserError("invalid headers state")

        if self._proto_on_chunk_header is not None:
            self._proto_on_chunk_header()

    cdef _on_chunk_complete(self):
        self._maybe_call_on_header()

        if self._proto_on_chunk_complete is not None:
            self._proto_on_chunk_complete()

    # Public API

    def get_http_version(self):
        cdef cparser.llhttp_t* parser = self._cparser
        return f"{parser.http_major}.{parser.http_minor}"

    def should_keep_alive(self):
        return bool(cparser.llhttp_should_keep_alive(self._cparser))

    def should_upgrade(self):
        cdef cparser.llhttp_t* parser = self._cparser
        return bool(parser.upgrade)

    def feed_data(self, data):
        cdef:
            size_t data_len
            cparser.llhttp_errno_t err
            Py_buffer *buf
            bint owning_buf = False
            char * err_pos

        # 如果 data 是一个 memoryview 实例
        if PyMemoryView_Check(data):
            # 返回指向 memoryview 的导出缓冲区私有副本的指针
            buf = PyMemoryView_GET_BUFFER(data)
            data_len = <size_t>buf.len
            err = cparser.llhttp_execute(self._cparser, <char*>buf.buf, data_len)
        else:
            buf = &self.py_buf
            # int PyObject_GetBuffer(PyObject *exporter, Py_buffer *view, int flags)
            # 向 输出器程序 发送请求，按照 flags 指定的内容填充 view。
            # 如果 输出器程序不能提供准确类型的缓冲区，必须 触发 PyExc_BufferError，设置 view->obj 为 NULL 并返回 -1。
            # 成功时，填充 view，将 view->obj 设为对 exporter 的新引用，并返回 0。
            # 当链式缓冲区提供程序将请求重定向到一个对象时，view->obj 可以引用该对象而不是 exporter (参见 缓冲区对象结构)。
            # PyObject_GetBuffer() 必须与 PyBuffer_Release() 同时调用成功，类似于 malloc() 和 free()。
            # 因此，消费者程序用完缓冲区后， PyBuffer_Release() 必须保证被调用一次。

            # 控制内存逻辑结构的标志按照复杂度的递减顺序列出。注意，每个标志包含它下面的所有标志。
            # 请求    PyBUF_SIMPLE
            # 形状    NULL
            # 步幅    NULL
            # 子偏移量 NULL
            PyObject_GetBuffer(data, buf, PyBUF_SIMPLE)
            owning_buf = True
            data_len = <size_t>buf.len

            err = cparser.llhttp_execute(self._cparser, <char*>buf.buf, data_len)

        try:
            if self._cparser.upgrade == 1 and err == cparser.HPE_PAUSED_UPGRADE:
                err_pos = cparser.llhttp_get_error_pos(self._cparser)
                cparser.llhttp_resume_after_upgrade(self._cparser)
                raise HttpParserUpgrade(err_pos - <char*>buf.buf)
        finally:
            if owning_buf:
                PyBuffer_Release(buf)

            if err != cparser.HPE_OK:
                e = parser_error_from_errno(self._cparser, <cparser.llhttp_errno_t> self._cparser.error)
                if isinstance(e, HttpParserCallbackError):
                    if self._last_error is not None:
                        e.__context__ = self._last_error
                        self._last_error = None
                    raise e


cdef class HttpRequestParser(HttpParser):

    def __init__(self, protocol: asyncio.Protocol):
        self._init(protocol, cparser.HTTP_REQUEST)

        self._proto_on_url = getattr(protocol, "on_url", None)
        if self._proto_on_url is not None:
            self._csettings.on_url = cb_on_url

    def get_method(self):
        cdef cparser.llhttp_t* parser = self._cparser
        return cparser.llhttp_method_name(<cparser.llhttp_method_t> parser.method)


cdef int cb_on_message_begin(cparser.llhttp_t* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._proto_on_message_begin()
    except BaseException as e:
        pyparser._last_error = e
        return -1
    else:
        return 0

cdef int cb_on_url(cparser.llhttp_t* parser, const char* at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._proto_on_url(at[:length])
    except BaseException as e:
        cparser.llhttp_set_error_reason(parser, "`on_url` callback error")
        pyparser._last_error = e
        return cparser.HPE_USER
    else:
        return 0

cdef int cb_on_status(cparser.llhttp_t* parser, const char* at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._proto_on_status(at[:length])
    except BaseException as e:
        cparser.llhttp_set_error_reason(parser, "`on_status` callback error")
        pyparser._last_error = e
        return cparser.HPE_USER
    else:
        return 0

cdef int cb_on_header_field(cparser.llhttp_t* parser, const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_header_field(at[:length])
    except BaseException as e:
        cparser.llhttp_set_error_reason(parser, "`on_header_field` callback error")
        pyparser._last_error = e
        return cparser.HPE_USER
    else:
        return 0


cdef int cb_on_header_value(cparser.llhttp_t* parser, const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_header_value(at[:length])
    except BaseException as e:
        cparser.llhttp_set_error_reason(parser, "`on_header_value` callback error")
        pyparser._last_error = e
        return cparser.HPE_USER
    else:
        return 0


cdef int cb_on_headers_complete(cparser.llhttp_t* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_headers_complete()
    except BaseException as e:
        pyparser._last_error = e
        return -1
    else:
        if pyparser._cparser.upgrade:
            return 1
        else:
            return 0


cdef int cb_on_body(cparser.llhttp_t* parser, const char *at, size_t length) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._proto_on_body(at[:length])
    except BaseException as e:
        cparser.llhttp_set_error_reason(parser, "`on_body` callback error")
        pyparser._last_error = e
        return cparser.HPE_USER
    else:
        return 0


cdef int cb_on_message_complete(cparser.llhttp_t* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._proto_on_message_complete()
    except BaseException as e:
        pyparser._last_error = e
        return -1
    else:
        return 0


cdef int cb_on_chunk_header(cparser.llhttp_t* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_chunk_header()
    except BaseException as e:
        pyparser._last_error = e
        return -1
    else:
        return 0


cdef int cb_on_chunk_complete(cparser.llhttp_t* parser) except -1:
    cdef HttpParser pyparser = <HttpParser>parser.data
    try:
        pyparser._on_chunk_complete()
    except BaseException as e:
        pyparser._last_error = e
        return -1
    else:
        return 0


cdef parser_error_from_errno(cparser.llhttp_t* parser, cparser.llhttp_errno_t errno):
    cdef bytes reason = cparser.llhttp_get_error_reason(parser)

    if errno in (cparser.HPE_CB_MESSAGE_BEGIN,
                 cparser.HPE_CB_HEADERS_COMPLETE,
                 cparser.HPE_CB_MESSAGE_COMPLETE,
                 cparser.HPE_CB_CHUNK_HEADER,
                 cparser.HPE_CB_CHUNK_COMPLETE,
                 cparser.HPE_USER):
        cls = HttpParserCallbackError

    elif errno == cparser.HPE_INVALID_STATUS:
        cls = HttpParserInvalidStatusError

    elif errno == cparser.HPE_INVALID_METHOD:
        cls = HttpParserInvalidMethodError

    elif errno == cparser.HPE_INVALID_URL:
        cls = HttpParserInvalidURLError

    else:
        cls = HttpParserError

    return cls(reason.decode(b"latin-1"))
