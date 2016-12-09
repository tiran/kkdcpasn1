#include <Python.h>
#include <stdio.h>

static const char command[] = "\n\
import sys\n\
from kkdcpasn1 import decode_kkdcp_request\n\
data = sys.stdin.buffer.read()\n\
decode_kkdcp_request(data)\n";


int main(int argc, char *argv[])
{
    PyObject *module, *sys_path, *o;
    PyCompilerFlags cf;

    cf.cf_flags = 0;
    Py_NoSiteFlag = 1;
    Py_NoUserSiteDirectory = 1;
    Py_IsolatedFlag = 0;
    Py_HashRandomizationFlag = 0;

    Py_InitializeEx(0);

    sys_path = PySys_GetObject("path");
    if (sys_path == NULL) {
        PyErr_Print();
        return 1;
    }
    o = PyUnicode_FromString(".");
    if (o == NULL) {
        PyErr_Print();
        return 1;
    }
    if (PyList_SetItem(sys_path, 0, o)) {
        PyErr_Print();
        return 1;
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    if (PyRun_SimpleStringFlags(command, &cf) != 0) {
        PyErr_Print();
        return 1;
    }

    Py_Finalize();
    return 0;
}
