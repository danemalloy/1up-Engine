#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "operations.h"

int main(int argc, char** argv)
{
  HANDLE process_snapshot{ 0 };
  PROCESSENTRY32W process_entry{};

  process_entry.dwSize = sizeof(PROCESSENTRY32W);

  process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  Process32FirstW(process_snapshot, &process_entry);

  do
  {
    if (wcscmp(process_entry.szExeFile, L"wesnoth.exe") == 0)
    {
      HANDLE process{ OpenProcess(PROCESS_ALL_ACCESS, true, process_entry.th32ProcessID) };

      if (!process)
      {
        std::cerr << "failed to open process" << std::endl;
        return 1;
      }

      char* p{ nullptr };

      long value{ strtol(argv[2], &p, 10) };

      if (strcmp(argv[1], "search") == 0)
      {
        search(process, value);
      }
      else if (strcmp(argv[1], "filter") == 0)
      {
        filter(process, value);
      }
      /*else if (strcmp(argv[1], "write") == 0)
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

  return 0;
}
