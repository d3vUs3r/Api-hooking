#include <iostream>
#include <Windows.h>

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;

#ifdef _M_IX86
# define SizePath 6
char messageBoxOriginalBytes[SizePath] = { 0 };
#else
# define SizePath 13
char messageBoxOriginalBytes[SizePath] = { 0 };
#endif

int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

    // print intercepted values from the MessageBoxA function
    std::cout << "Start hooked function\n";
    std::cout << "Text: " << lpText << "\nCaption: " << lpCaption << std::endl;


    // unpatch MessageBoxA
    //DWORD oldProtect;
    //VirtualProtectEx(GetCurrentProcess(), (LPVOID)messageBoxAddress, sizeof(messageBoxOriginalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
    BOOL unhooked = WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
    //VirtualProtectEx(GetCurrentProcess(), (LPVOID)messageBoxAddress, sizeof(messageBoxOriginalBytes), oldProtect, &oldProtect);

    if (!unhooked) {
        std::cerr << "Failed to unhook MessageBoxA" << std::endl;
    }

    // call the original MessageBoxA
    return MessageBoxA(NULL, lpText, lpCaption, uType);

}

int main()
{
    // show messagebox before hooking
    MessageBoxA(NULL, "hi", "hi", MB_OK);

    HINSTANCE library = LoadLibraryA("user32.dll");
    SIZE_T bytesRead = 0;


    // get address of the MessageBox function in memory
    messageBoxAddress = GetProcAddress(library, "MessageBoxA");

    if (messageBoxAddress == NULL) {
        std::cerr << "Failed to get address of MessageBoxA" << std::endl;
        return 1;
    }

    // save the first 6 bytes or 13 of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesRead);

    // create a patch "push <address of new MessageBoxA); ret"
    void* hookedMessageBoxAddress = &HookedMessageBox;

    char patch[SizePath] = { 0 };
#ifdef _M_IX86
     // mov eax, <hookedMessageBoxAddress>
    patch[0] = 0x68;
    memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
    //  ret
    patch[5] = 0xC3;
#else
    // mov rax, <hookedMessageBoxAddress>
    patch[0] = 0x48;
    patch[1] = 0xB8;
    memcpy_s(patch + 2, 8, &hookedMessageBoxAddress, 8);
    // jmp rax
    patch[10] = 0xFF;
    patch[11] = 0xE0;
    // nop
    patch[12] = 0x90;
#endif
    // patch the MessageBoxA
    BOOL patched = WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, patch, sizeof(patch), &bytesWritten);

    if (!patched) {
        std::cerr << "Failed to patch MessageBoxA" << std::endl;
        return 1;
    }

    // show messagebox after hooking
    MessageBoxA(NULL, "Test", "Hello world !", MB_OK);

    return 0;
}
