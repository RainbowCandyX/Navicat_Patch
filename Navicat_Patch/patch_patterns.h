#pragma once

#include <string_view>

namespace navicat_patch
{
	struct PatchDefinition
	{
		const wchar_t* moduleName;
		std::string_view search;
		std::string_view replacement;
		std::string_view expected;
	};

	inline constexpr PatchDefinition kDefinitions[] =
	{
		{
			L"libcc.dll",
			"4C8BC0483BCB7F??483BD87F??4084F675??488B07",
			"4C8BC0483BCB7F00483BD87F004084F6EB??488B07",
			"4C8BC0483BCB7F1F483BD87F1A4084F67511488B07",
		},
		{
			L"navicat.exe",
			"8B73088B7B1889F083E80183F8FF",
			"FF4308FF4318B00131C09083F8FF",
			"8B73088B7B1889F083E80183F8FF",
		},
	};
}
