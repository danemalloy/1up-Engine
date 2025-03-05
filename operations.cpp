#include <iostream>
#include <Windows.h>
#include <vector>
#include "operations.h"

#define NOMINMAX

#include <windef.h>

constexpr auto buffer_size = 0x00000808;
constexpr DWORD PAGE_READABLE_FLAGS =
PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;

void scan(HANDLE process, uint64_t val)
{
  FILE* temp{ nullptr };
  fopen_s(&temp, "scan_results.txt", "w");
  if (!temp)
  {
    std::cerr << "failed to open file(s)" << std::endl;
    return;
  }

  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);

  MEMORY_BASIC_INFORMATION memory_info{};

  uint64_t current_address{ (uint64_t)system_info.lpMinimumApplicationAddress };
  uint64_t end_address{ (uint64_t)system_info.lpMaximumApplicationAddress };

  std::vector<unsigned char> buffer(buffer_size);

  int total_found{ 0 };

  while (current_address < end_address)
  {
    if (!VirtualQueryEx(process, (LPCVOID)current_address, &memory_info, sizeof(memory_info)))
    {
      current_address += buffer_size;
      continue;
    }

    if (memory_info.State != MEM_COMMIT || !(memory_info.Protect & PAGE_READABLE_FLAGS))
    {
      current_address += memory_info.RegionSize;
      continue;
    }

    SIZE_T bytes_read{ 0 };
    SIZE_T bytes_to_read{ (((memory_info.RegionSize) < (static_cast<SIZE_T>(buffer_size))) ? (memory_info.RegionSize) : (static_cast<SIZE_T>(buffer_size))) };
    if (!ReadProcessMemory(process, (LPCVOID)current_address, buffer.data(), bytes_to_read, &bytes_read))
    {
      current_address += memory_info.RegionSize;
      continue;
    }

    if (bytes_read < sizeof(uint64_t))
    {
      current_address += memory_info.RegionSize;
      continue;
    }

    for (SIZE_T offset{ 0 }; offset + sizeof(uint64_t) <= bytes_read; offset += sizeof(uint64_t))
    {
      uint64_t value{ 0 };

      memcpy(&value, &buffer[offset], sizeof(value));

      if (value == val)
      {
        fprintf(temp, "%llX\n", (uint64_t)(current_address + offset));
        total_found++;
      }
    }

    current_address += memory_info.RegionSize;
  }

  std::cout << "scan complete.\naddresses found: " << std::dec << total_found << std::endl;

  fclose(temp);
}

void filter(HANDLE process, uint64_t val)
{
  FlushInstructionCache(process, NULL, 0);

  FILE* temp{ nullptr };
  FILE* temp_filtered{ nullptr };

  fopen_s(&temp, "scan_results.txt", "r");
  fopen_s(&temp_filtered, "scan_results_filtered.txt", "w");
  if (!temp || !temp_filtered)
  {
    std::cerr << "failed to open file(s)" << std::endl;
    return;
  }

  std::vector<unsigned char> buffer(buffer_size);

  uint64_t address{ 0 };
  int filtered{ 0 };

  while (fscanf_s(temp, "%llx\n", &address) == 1)
  {
    if (address == 0)
    {
      continue;
    }

    MEMORY_BASIC_INFORMATION memory_info{};
    if (VirtualQueryEx(process, (LPCVOID)address, &memory_info, sizeof(memory_info)))
    {
      if (memory_info.State != MEM_COMMIT || !(memory_info.Protect & PAGE_READABLE_FLAGS))
      {
        continue;
      }
    }

    SIZE_T bytes_read{ 0 };
    SIZE_T bytes_to_read{ (((memory_info.RegionSize) < (static_cast<SIZE_T>(buffer_size))) ? (memory_info.RegionSize) : (static_cast<SIZE_T>(buffer_size))) };
    if (!ReadProcessMemory(process, (LPCVOID)address, buffer.data(), bytes_to_read, &bytes_read))
    {
      continue;
    }
    
    if (bytes_read < sizeof(uint64_t))
    {
      continue;
    }
    
    for (SIZE_T offset{ 0 }; offset + sizeof(uint64_t) <= bytes_read; offset += sizeof(uint64_t))
    {
      uint64_t value{ 0 };

      memcpy(&value, &buffer[offset], sizeof(value));

      std::cout << "value: " << value << std::endl;

      if (value == val)
      {
        fprintf(temp_filtered, "%llx\n", (unsigned long long)(address + offset));
        filtered++;
      }
    }
  }

  fclose(temp);
  fclose(temp_filtered);

  fopen_s(&temp, "scan_results.txt", "w");
  fopen_s(&temp_filtered, "scan_results_filtered.txt", "r");
  if (!temp || !temp_filtered)
  {
    std::cerr << "failed to open file(s)" << std::endl;
    return;
  }

  uint64_t filtered_address{ 0 };
  while (fscanf_s(temp_filtered, "%llx\n", &filtered_address) == 1)
  {
    fprintf(temp, "%llx\n", (uint64_t)(filtered_address));
  }

  fclose(temp);
  fclose(temp_filtered);

  remove("scan_results_filtered.txt");

  std::cout << "filter complete.\naddresses found: " << filtered << std::endl;
}
