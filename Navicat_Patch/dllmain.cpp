#include <Windows.h>
#include "patch_patterns.h"
#include "winmm_exports.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <string_view>

#pragma comment(lib, "user32.lib")

namespace
{
	constexpr std::size_t kMaxPatchSize = 32;
	constexpr unsigned int kFirstOrdinal = 2;
	constexpr std::size_t kExportCount = 181;

	INIT_ONCE gProxyOnce = INIT_ONCE_STATIC_INIT;
	std::array<FARPROC, kExportCount> gProcedures{};

	struct PatchMessage
	{
		const wchar_t* text = nullptr;
		UINT icon = MB_ICONERROR;
	};

	std::array<PatchMessage, 8> gPatchMessages{};
	std::size_t gPatchMessageCount = 0;
	volatile LONG gPatchMessagesShown = 0;

	void RecordPatchMessage(const wchar_t* text, UINT icon = MB_ICONERROR) noexcept
	{
		if(gPatchMessageCount < gPatchMessages.size())
			gPatchMessages[gPatchMessageCount++] = { text, icon };
		else
			gPatchMessages.back() = { L"补丁提示数量超过上限，部分消息未能显示。", MB_ICONERROR };
	}

	void ShowPatchMessages() noexcept
	{
		if(gPatchMessageCount == 0 || InterlockedCompareExchange(&gPatchMessagesShown, 1, 0) != 0)
			return;

		for(std::size_t index = 0; index < gPatchMessageCount; ++index)
			MessageBoxW(nullptr, gPatchMessages[index].text, L"Navicat 补丁", MB_OK | gPatchMessages[index].icon);
	}

	struct BytePattern
	{
		std::array<BYTE, kMaxPatchSize> bytes{};
		std::array<BYTE, kMaxPatchSize> mask{};
		std::size_t size = 0;
	};

	struct PatchSite
	{
		BYTE* address = nullptr;
		std::array<BYTE, kMaxPatchSize> before{};
		std::array<BYTE, kMaxPatchSize> after{};
		std::size_t size = 0;
		DWORD protection = 0;
	};

	int HexDigit(char value) noexcept
	{
		if(value >= '0' && value <= '9')
			return value - '0';
		if(value >= 'A' && value <= 'F')
			return value - 'A' + 10;
		if(value >= 'a' && value <= 'f')
			return value - 'a' + 10;
		return -1;
	}

	bool ParsePattern(std::string_view text, BytePattern& output) noexcept
	{
		if(text.empty() || text.size() % 2 != 0 || text.size() / 2 > kMaxPatchSize)
			return false;

		output = {};
		output.size = text.size() / 2;
		for(std::size_t index = 0; index < output.size; ++index)
		{
			const char high = text[index * 2];
			const char low = text[index * 2 + 1];
			if(high == '?' && low == '?')
				continue;

			const int highValue = HexDigit(high);
			const int lowValue = HexDigit(low);
			if(highValue < 0 || lowValue < 0)
				return false;
			output.bytes[index] = static_cast<BYTE>((highValue << 4) | lowValue);
			output.mask[index] = 0xFF;
		}
		return true;
	}

	bool Matches(const BYTE* address, const BytePattern& pattern) noexcept
	{
		for(std::size_t index = 0; index < pattern.size; ++index)
		{
			if(pattern.mask[index] != 0 && address[index] != pattern.bytes[index])
				return false;
		}
		return true;
	}

	bool IsReadable(const MEMORY_BASIC_INFORMATION& region) noexcept
	{
		if(region.State != MEM_COMMIT || (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
			return false;

		switch(region.Protect & 0xFF)
		{
			case PAGE_READONLY:
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
			case PAGE_EXECUTE_READ:
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				return true;
			default:
				return false;
		}
	}

	BYTE* FindUnique(HMODULE module, const BytePattern& pattern) noexcept
	{
		auto* base = reinterpret_cast<BYTE*>(module);
		const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		if(dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000)
			return nullptr;

		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
		if(nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
			nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt->FileHeader.NumberOfSections > 96)
			return nullptr;

		BYTE* found = nullptr;
		const auto* sections = IMAGE_FIRST_SECTION(nt);
		const std::size_t imageSize = nt->OptionalHeader.SizeOfImage;
		for(WORD sectionIndex = 0; sectionIndex < nt->FileHeader.NumberOfSections; ++sectionIndex)
		{
			const auto& section = sections[sectionIndex];
			if((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
				continue;

			const std::size_t length = section.Misc.VirtualSize;
			if(section.VirtualAddress > imageSize || length > imageSize - section.VirtualAddress)
				return nullptr;
			const auto sectionStart = reinterpret_cast<std::uintptr_t>(base + section.VirtualAddress);
			const auto sectionEnd = sectionStart + length;
			auto cursor = sectionStart;
			while(cursor < sectionEnd)
			{
				MEMORY_BASIC_INFORMATION region{};
				if(VirtualQuery(reinterpret_cast<const void*>(cursor), &region, sizeof(region)) != sizeof(region))
					return nullptr;
				const auto regionEnd = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
				if(regionEnd <= cursor)
					return nullptr;
				const auto end = regionEnd < sectionEnd ? regionEnd : sectionEnd;
				if(IsReadable(region) && end - cursor >= pattern.size)
				{
					for(auto candidate = cursor; candidate <= end - pattern.size; ++candidate)
					{
						auto* address = reinterpret_cast<BYTE*>(candidate);
						if(address[0] != pattern.bytes[0] || !Matches(address, pattern))
							continue;
						if(found != nullptr)
							return nullptr;
						found = address;
					}
				}
				cursor = end;
			}
		}
		return found;
	}

	bool PreparePatch(const navicat_patch::PatchDefinition& definition, PatchSite& site) noexcept
	{
		const HMODULE module = GetModuleHandleW(definition.moduleName);
		BytePattern search{};
		BytePattern replacement{};
		BytePattern expected{};
		if(module == nullptr || !ParsePattern(definition.search, search) ||
			!ParsePattern(definition.replacement, replacement) || !ParsePattern(definition.expected, expected) ||
			search.size != replacement.size || search.size != expected.size)
			return false;

		site.address = FindUnique(module, search);
		if(site.address == nullptr || !Matches(site.address, expected))
			return false;

		site.size = search.size;
		std::memcpy(site.before.data(), site.address, site.size);
		for(std::size_t index = 0; index < site.size; ++index)
			site.after[index] = replacement.mask[index] != 0 ? replacement.bytes[index] : site.before[index];
		return true;
	}

	bool RestoreProtections(std::array<PatchSite, 2>& sites, std::size_t count) noexcept
	{
		bool restored = true;
		for(std::size_t index = 0; index < count; ++index)
		{
			DWORD discarded = 0;
			if(!VirtualProtect(sites[index].address, sites[index].size, sites[index].protection, &discarded))
			{
				RecordPatchMessage(L"恢复补丁所在页面的保护属性失败。\n");
				restored = false;
			}
		}
		return restored;
	}

	void ApplyRuntimePatches() noexcept
	{
		std::array<PatchSite, 2> sites{};
		static_assert(std::size(navicat_patch::kDefinitions) == 2);
		for(std::size_t index = 0; index < sites.size(); ++index)
		{
			if(!PreparePatch(navicat_patch::kDefinitions[index], sites[index]))
			{
				RecordPatchMessage(L"目标模块、唯一特征或原始字节不匹配，未应用任何补丁。\n");
				return;
			}
		}

		for(std::size_t index = 0; index < sites.size(); ++index)
		{
			if(!VirtualProtect(sites[index].address, sites[index].size, PAGE_EXECUTE_READWRITE, &sites[index].protection))
			{
				RestoreProtections(sites, index);
				RecordPatchMessage(L"获取页面写权限失败，未应用任何补丁。\n");
				return;
			}
		}

		for(const auto& site : sites)
			std::memcpy(site.address, site.after.data(), site.size);

		bool flushed = true;
		for(const auto& site : sites)
		{
			if(!FlushInstructionCache(GetCurrentProcess(), site.address, site.size))
				flushed = false;
		}
		if(!flushed)
		{
			for(const auto& site : sites)
				std::memcpy(site.address, site.before.data(), site.size);
			for(const auto& site : sites)
			{
				if(!FlushInstructionCache(GetCurrentProcess(), site.address, site.size))
					RecordPatchMessage(L"回滚后的指令缓存刷新失败。\n");
			}
			RestoreProtections(sites, sites.size());
			RecordPatchMessage(L"指令缓存刷新失败，已写回两组原始字节。\n");
			return;
		}

		if(!RestoreProtections(sites, sites.size()))
			RecordPatchMessage(L"两组字节已写入，但页面保护恢复失败。\n");
	}

	bool IsTargetHost() noexcept
	{
		std::array<wchar_t, MAX_PATH> path{};
		const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
		if(length == 0 || length >= path.size())
			return false;
		const wchar_t* separator = std::wcsrchr(path.data(), L'\\');
		const wchar_t* name = separator == nullptr ? path.data() : separator + 1;
		return _wcsicmp(name, L"navicat.exe") == 0;
	}

	BOOL CALLBACK InitializeSystemWinmm(PINIT_ONCE, PVOID, PVOID*) noexcept
	{
		std::array<wchar_t, MAX_PATH> path{};
		constexpr wchar_t suffix[] = L"\\winmm.dll";
		const UINT length = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size()));
		if(length == 0 || length >= path.size() || length + std::size(suffix) > path.size())
		{
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
		std::memcpy(path.data() + length, suffix, sizeof(suffix));
		const HMODULE module = LoadLibraryExW(path.data(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if(module == nullptr)
			return FALSE;

		static_assert(std::size(navicat_patch::kExportNames) == kExportCount);
		for(std::size_t index = 0; index < kExportCount; ++index)
		{
			const char* name = navicat_patch::kExportNames[index];
			const auto ordinal = static_cast<WORD>(index + kFirstOrdinal);
			gProcedures[index] = GetProcAddress(module, name == nullptr ? MAKEINTRESOURCEA(ordinal) : name);
			if(gProcedures[index] == nullptr)
			{
				FreeLibrary(module);
				SetLastError(ERROR_PROC_NOT_FOUND);
				return FALSE;
			}
		}
		return TRUE;
	}
}

extern "C" FARPROC ResolveWinmmExport(unsigned int ordinal) noexcept
{
	const DWORD savedError = GetLastError();
	if(ordinal < kFirstOrdinal || ordinal - kFirstOrdinal >= kExportCount ||
		!InitOnceExecuteOnce(&gProxyOnce, InitializeSystemWinmm, nullptr, nullptr))
	{
		MessageBoxW(nullptr, L"加载系统winmm.dll或解析导出失败。\n", L"Navicat 补丁", MB_OK | MB_ICONERROR);
		ExitProcess(ERROR_PROC_NOT_FOUND);
	}
	const FARPROC procedure = gProcedures[ordinal - kFirstOrdinal];
	ShowPatchMessages();
	SetLastError(savedError);
	return procedure;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
	if(reason == DLL_PROCESS_ATTACH && IsTargetHost())
		ApplyRuntimePatches();
	return TRUE;
}

