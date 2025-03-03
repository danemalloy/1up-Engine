#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "operations.h"

int main(int argc, char** argv)
{
  if (argc < 3)
  {
    std::cerr << "usage: " << argv[0] << " <operation> <value>\n";
    return 1;
  }

  HANDLE process_snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
  if (process_snapshot == INVALID_HANDLE_VALUE)
  {
    std::cerr << "failed to take process snapshot\n";
    return 1;
  }

  PROCESSENTRY32W process_entry{};
  process_entry.dwSize = sizeof(PROCESSENTRY32W);

  if (!Process32FirstW(process_snapshot, &process_entry))
  {
    std::cerr << "failed to retrieve first process\n";
    CloseHandle(process_snapshot);
    return 1;
  }

  do
  {
    if (wcscmp(process_entry.szExeFile, L"wesnoth.exe") == 0)
    {
      HANDLE process{ OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, process_entry.th32ProcessID) };
      if (!process)
      {
        std::cerr << "failed to open process (insufficient permissions or process doesn't exist)\n";
        CloseHandle(process_snapshot);
        return 1;
      }

      char* p{ nullptr };

      uintptr_t value{ strtoull(argv[2], &p, 10) };

      if (strcmp(argv[1], "scan") == 0)
      {
        scan(process, value);
      }
      /*else if (strcmp(argv[1], "filter") == 0)
      {
        filter(process, value);
      }
      else if (strcmp(argv[1], "write") == 0)
      {
        write(process, value, argv[3]);
      }*/
      else
      {
        std::cerr << "invalid operation" << std::endl;
      }

      CloseHandle(process);
      break;
    }
  } while (Process32NextW(process_snapshot, &process_entry));

  CloseHandle(process_snapshot);

  return 0;
}
