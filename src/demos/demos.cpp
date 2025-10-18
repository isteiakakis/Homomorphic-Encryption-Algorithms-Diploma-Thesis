#include "demos.h"
#include <iostream>
#include <string_view>

using namespace std;

int main(int argc, const char **argv)
{
    if (argc != 3) {
        cout << "usage: demo <demo_suite> <demo_name>" << '\n';
        exit(1);
    }

#define RUN_DEMO_IFELSE(demo_suite) \
    if (argv[1] == #demo_suite##sv) \
        demo_suite##_demo(argv); \
    else


    RUN_DEMO_IFELSE(client)
    RUN_DEMO_IFELSE(client_server_rookie)
    RUN_DEMO_IFELSE(fft)
    RUN_DEMO_IFELSE(math_operations)
    RUN_DEMO_IFELSE(matrix_operations)
    RUN_DEMO_IFELSE(server)
        cout << "No such demo." << '\n';

    return 0;
}
