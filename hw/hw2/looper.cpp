#include <iostream>
#include <string>
int main()
{
    std::cout << "Start" << std::endl;
    int n = 0;
    std::cin >> n;
    for (int i = 0; i < n; i++) {
        std::cout << "i:" << i << std::endl;
    }
    return 0;
}
