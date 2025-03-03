#include <iostream>
#include <Windows.h>
#include "operations.h"

#define buffer_size 0x00000808

void search(const HANDLE process, const int val)
{
  FILE* temp{ nullptr };
  fopen_s(&temp, "scan_results.txt", "w");
  if (!temp)
  {
    std::cerr << "failed to open file" << std::endl;
    return;
  }

  unsigned char* buffer{ (unsigned char*)calloc(1, buffer_size) };
  if (!buffer)
  {
    std::cerr << "failed to allocate buffer" << std::endl;
    return;
  }

  unsigned long long bytes_read{ 0 };

  for (DWORD address = 0x00000000; address < 0x7FFFFFFF; address += buffer_size)
  {
    if (!ReadProcessMemory(process, (LPCVOID)address, buffer, buffer_size, &bytes_read))
    {
      std::cerr << "failed to read process memory at address " << std::hex << (LPCVOID)address << "\n";
      continue;
    }

    for (int offset{ 0 }; offset < buffer_size - 4; offset += 4)
    {
      DWORD value{ 0 };

      memcpy(&value, &buffer[offset], sizeof(value));

      if (!value)
      {
        std::cerr << "failed to get value at address " << std::hex << (LPCVOID)address << "\n";
        continue;
      }

      if (value == val)
      {
        fprintf(temp, "%x\n", address + offset);
        std::cout << "found value at address " << std::hex << (LPCVOID)address << "\n";
      }
    }
  }

  fclose(temp);
  free(buffer);
}

void filter(const HANDLE process, const int val)
{
  FILE* temp{ NULL };
  FILE* temp_filtered{ NULL };

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
    DWORD value{ 0 };
    
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
}
