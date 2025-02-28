#include <iostream>

// windows api includes
#include <Windows.h>

// any process that has PROCESS_VM_READ access can call this function
/// if the area to read is not accessible, the function will fail
BOOL ReadProcessMemory(
  [in] HANDLE hProcess,               // handle to the process whose memory we will be reading
  [in] LPCVOID lpBaseAddress,         // pointer to the base address in the process that we will read from
  [out] LPVOID lpBuffer,              // pointer to the buffer that will receive the data read from the process
  [in] SIZE_T nSize,                  // number of bytes to read from the process
  [out] SIZE_T* lpNumberOfBytesRead   // pointer to the variable that receives number of bytes read from the process
)
{

}

int main(int argc, char** argv)
{
  DWORD changeValue{ 0 };
  DWORD bytesRead{ 0 };

  return 0;
}
