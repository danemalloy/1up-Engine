#include <iostream>
#include <Windows.h>
#include <vector>
#include "operations.h"

constexpr auto buffer_size{ 0x00000808  };

void scan(const HANDLE process, uintptr_t val)
{
  FILE* temp{ nullptr };
  fopen_s(&temp, "scan_results.txt", "w");
  if (!temp)
  {
    std::cerr << "failed to open file" << std::endl;
    return;
  }

  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);

  MEMORY_BASIC_INFORMATION memory_info{};

  uintptr_t current_address{ (uintptr_t)system_info.lpMinimumApplicationAddress };
  uintptr_t end_address{ (uintptr_t)system_info.lpMaximumApplicationAddress };

  std::vector<unsigned char> buffer(buffer_size);

  while (current_address < end_address)
  {
    if (!VirtualQueryEx(process, (LPCVOID)current_address, &memory_info, sizeof(memory_info)))
    {
      std::cerr << "failed to query memory" << "\n";
      current_address += buffer_size;
      continue;
    }

    bool is_readable{ (memory_info.Protect & PAGE_READWRITE) || (memory_info.Protect & PAGE_READONLY) };
    if (memory_info.State != MEM_COMMIT || !is_readable)
    {
      std::cerr << "memory not readable" << "\n";
      current_address += memory_info.RegionSize;
      continue;
    }

    SIZE_T bytes_read{ 0 };
    if (!ReadProcessMemory(process, (LPCVOID)current_address, buffer.data(), memory_info.RegionSize, &bytes_read))
    {
      std::cerr << "failed to read memory" << "\n";
      current_address += memory_info.RegionSize;
      continue;
    }

    if (bytes_read < sizeof(int))
    {
      std::cerr << "failed to read enough bytes" << "\n";
      current_address += memory_info.RegionSize;
      continue;
    }

    for (SIZE_T offset = 0; offset < bytes_read - sizeof(int); offset++)
    {
      uintptr_t value{ 0 };

      memcpy(&value, &buffer[offset], sizeof(value));

      if (value == val)
      {
        fprintf(temp, "%llX\n", (unsigned long long)(current_address + offset));
        std::cout << "found value at address: " << std::hex << (void*)(current_address + offset) << "\n";
      }
    }

    current_address += memory_info.RegionSize;
  }

  std::cout << "scan complete" << std::endl;

  fclose(temp);
}

/*void filter(const HANDLE process, const int val)
{
  FILE* temp{ nullptr };
  FILE* temp_filtered{ nullptr };

  fopen_s(&temp, "scan_results.txt", "r");
  fopen_s(&temp_filtered, "scan_results_filtered.txt", "w");
  if (!temp || !temp_filtered)
  {
    std::cerr << "failed to open file" << std::endl;
    return;
  }

  DWORD address{ 0 };

  while (fscanf_s(temp, "%x\n", &address) != EOF)
  {
    uintptr_t value{ 0 };
    
    unsigned long long bytes_read{ 0 };

    ReadProcessMemory(process, (LPCVOID)address, &value, sizeof(value), &bytes_read);

    if (!value)
    {
      continue;
    }

    if (value == val)
    {
      fprintf(temp_filtered, "%x\n", address);
      std::cout << "found value at address " << std::hex << address << "\n";
    }
  }

  fclose(temp);
  fclose(temp_filtered);

  fopen_s(&temp, "scan_results.txt", "w");
  fopen_s(&temp_filtered, "scan_results_filtered.txt", "r");

  while (fscanf_s(temp_filtered, "%x\n", &address) != EOF)
  {
    fprintf(temp, "%x\n", address);
  }

  fclose(temp);
  fclose(temp_filtered);

  remove("scan_results_filtered.txt");
}*/
