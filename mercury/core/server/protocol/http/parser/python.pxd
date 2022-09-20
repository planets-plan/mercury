cimport cpython


cdef extern from "Python.h":
    # MemoryView 对象
    # 一个 memoryview 对象C级别的 缓冲区接口 暴露为一个可以像任何其他对象一样传递的 Python 对象。

    # Py_buffer *PyMemoryView_GET_BUFFER(PyObject *mview)
    # 返回指向 memoryview 的导出缓冲区私有副本的指针。 mview 必须 是一个 memoryview 实例；
    # 这个宏不检查它的类型，你必须自己检查，否则你将面临崩溃风险。
    cpython.Py_buffer* PyMemoryView_GET_BUFFER(object)
    # int PyMemoryView_Check(PyObject *obj)
    # 如果 obj 是一个 memoryview 对象则返回真值。 目前不允许创建 memoryview 的子类。 此函数总是会成功执行。
    bint PyMemoryView_Check(object)