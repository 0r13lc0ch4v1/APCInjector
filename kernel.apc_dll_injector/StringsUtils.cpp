#include "Definitions.h"
#include "StringsUtils.h"

BOOLEAN IsStringEndWith(
	_In_ const wchar_t * pString,
	_In_ const wchar_t * pSuffix
)
{
	ULONG ulStringLength = 0;
	ULONG ulSuffixLength = 0;

	if (NULL == pString || NULL == pSuffix)
	{
		return FALSE;
	}

	ulStringLength = GetStringLength(pString);
	ulSuffixLength = GetStringLength(pSuffix);

	if (0 == ulSuffixLength)
	{
		return TRUE;
	}

	if (ulSuffixLength > ulStringLength)
	{
		return FALSE;
	}

	return StringNCompare(pString + (ulStringLength - ulSuffixLength), pSuffix, ulSuffixLength);
}