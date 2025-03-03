#include <iostream>
// windows api includes
#include <Windows.h>

int main()
{
  HWND game_window = FindWindow(NULL, L"The Battle for Wesnoth - 1.18.4");

  if (!game_window) {
    std::cerr << "game window not found" << "\n";
    return 1;
  }

  DWORD process_id{ 0 };
  GetWindowThreadProcessId(game_window, &process_id);

  HANDLE game_process{ OpenProcess(PROCESS_ALL_ACCESS, true, process_id) };

  if (!game_process) {
    std::cerr << "failed to open process | error code: " << GetLastError() << "\n";
    return 1;
  }

  uintptr_t input_address{ 0 };

  std::cout << "enter memory address: ";
  std::cin >> std::hex >> input_address;

  void* memory_address{ (void*)input_address };
  DWORD memory_value{ 0 };

  unsigned long long bytes_read{ 0 };

  if (!ReadProcessMemory(game_process, (LPCVOID)memory_address, &memory_value, sizeof(memory_value), &bytes_read))
  {
    std::cerr << "failed to read value of process memory | error code: " << GetLastError() << "\n";
    return 1;
  }

  unsigned int input_write_value{ 0 };
  unsigned long long bytes_written{ 0 };

  std::cout << "enter value to write: ";
  std::cin >> std::dec >> input_write_value;

  DWORD write_value{ input_write_value };

  std::cout << "writing value " << write_value << " to memory address..." << "\n";

  if (!WriteProcessMemory(game_process, (LPVOID)memory_address, &write_value, sizeof(write_value), &bytes_written))
  {
    std::cerr << "failed to write value to process memory | error code: " << GetLastError() << "\n";
    return 1;
  }

  std::cout << "address: " << memory_address << "\n" << "previous value: " << memory_value << "\n" << "new value: " << write_value << "\n";

  std::cin.ignore();
  std::cin.get();

  return 0;
}
