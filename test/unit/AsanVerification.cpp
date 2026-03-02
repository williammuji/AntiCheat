#include <iostream>
#include <vector>
#include <string>

// A simple program to demonstrate ASan detection and verification.
// Usage: .\AsanVerification.exe [bug_type]
// bug_type: 1 = heap-overflow, 2 = use-after-free, 0 = clean

void TriggerHeapOverflow() {
    std::cout << "[ASan] Triggering Heap Buffer Overflow..." << std::endl;
    int* array = new int[10];
    array[15] = 42; // Out of bounds
    delete[] array;
}

void TriggerUseAfterFree() {
    std::cout << "[ASan] Triggering Use-After-Free..." << std::endl;
    int* p = new int(100);
    delete p;
    std::cout << "[ASan] Accessing deleted memory: " << *p << std::endl;
}

int main(int argc, char** argv) {
    int bugType = 0;
    if (argc > 1) {
        bugType = std::stoi(argv[1]);
    }

    std::cout << "=== AntiCheat ASan Verification Tool ===" << std::endl;
    std::cout << "Target: x86 Debug with ASan enabled." << std::endl;

    if (bugType == 1) {
        TriggerHeapOverflow();
    } else if (bugType == 2) {
        TriggerUseAfterFree();
    } else {
        std::cout << "[OK] Running clean execution. No memory errors expected." << std::endl;
        int* p = new int[10];
        for(int i=0; i<10; ++i) p[i] = i;
        delete[] p;
        std::cout << "[OK] Memory allocated and freed correctly." << std::endl;
    }

    return 0;
}
