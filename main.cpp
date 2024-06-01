#include <Windows.h>

bool hookfunc(void* target_address, void* our_hook_func, int hook_byte_len)
{
	if (hook_byte_len >= 5)
	{
		DWORD old_protection;
		VirtualProtect(target_address, hook_byte_len, PAGE_EXECUTE_READWRITE, &old_protection);
		
		DWORD relative_addr = ((DWORD)our_hook_func - (DWORD)target_address) - 5;

		*(BYTE*)target_address = 0xE9; // jump opcode
		*(DWORD*)((DWORD)target_address + 1) = relative_addr;

		DWORD temp_protection;
		VirtualProtect(target_address, hook_byte_len, old_protection, &temp_protection);	

		return true;

	}
	else
	{
		return false;
	}
}

DWORD_PTR jmp_back;

__declspec(naked) void ourfunc()
{
	__asm
	{
		sub eax, 0
		jmp jmp_back
	}
}

DWORD WINAPI MainThread(LPVOID param)
{
	int hook_len = 6;
	//DWORD hook_address = 0x005F2517;
	//jmp_back = hook_address + hook_len;

	DWORD hook_addr = 0x003213EA;
	jmp_back = hook_addr + hook_len;

	if (hookfunc((void*)hook_addr, ourfunc, hook_len))
	{
		MessageBox(NULL, L"Hook worked", L"lofty_hook", MB_OK);
	}
	else
	{
		MessageBox(NULL, L"Hook failed", L"lofty_hook", MB_ICONERROR);
	}

	while (true)
	{

		if (GetAsyncKeyState(VK_HOME)&1)
		{
			break;
		}
		
		Sleep(100);
	}

	MessageBox(NULL, L"Uninjected hook", L"lofty_hook", MB_ICONASTERISK);
	
	FreeLibraryAndExitThread((HMODULE)param, NULL);

	return 0;

}

BOOL WINAPI DllMain(HINSTANCE hdll, DWORD dwreason, LPVOID lparam)
{
	switch (dwreason)
	{
	case DLL_PROCESS_ATTACH:
	{
		CreateThread(NULL, NULL, MainThread, hdll, NULL, NULL);
		break;
	}

	}

	return TRUE;
}



