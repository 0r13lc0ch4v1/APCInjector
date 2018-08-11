#pragma once

#include "Definitions.h"

template <class T>
BOOLEAN StringNCompare(
	_In_ const T * pString1,
	_In_ const T * pString2,
	_In_ const ULONG ulMaxLen
)
{
	ULONG ulIndex = 0;

	if (NULL == pString1 || NULL == pString2)
	{
		return FALSE;
	}

	for (ulIndex = 0; ulIndex < ulMaxLen; ulIndex++)
	{
		if ((NULL == pString1[ulIndex]) || (pString1[ulIndex] != pString2[ulIndex]))
		{
			return (pString1[ulIndex] - pString2[ulIndex]) ? FALSE : TRUE;
		}
	}

	return TRUE;
}

template <class T>
ULONG GetStringLength(
	_In_ const T * pString,
	_In_ const ULONG ulMaxLen = MAX_PATH
)
{
	ULONG ulIndex = 0;
	ULONG ulStringLength = 0;

	if (NULL == pString)
	{
		return 0;
	}
	__try
	{
		for (ulIndex = 0; (ulIndex < ulMaxLen) && pString[ulIndex]; ulIndex++)
		{
			ulStringLength++;
		}
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		DbgPrint("GetStringLength: ulIndex = %d", ulIndex);
		ulStringLength = 0;
	}

	return ulStringLength;
}

BOOLEAN IsStringEndWith(
	_In_ const wchar_t * pString,
	_In_ const wchar_t * pSuffix
);