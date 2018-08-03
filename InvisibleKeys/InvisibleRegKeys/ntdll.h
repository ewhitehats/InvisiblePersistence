#pragma once
#include <windows.h>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef
NTSTATUS(NTAPI *_NtSetValueKey)(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID Data,
	IN ULONG DataSize
	);

_NtSetValueKey NtSetValueKey = NULL;

typedef
VOID(NTAPI * _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

_RtlInitUnicodeString RtlInitUnicodeString = NULL;

typedef
NTSTATUS(NTAPI *_NtDeleteValueKey)(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName
	);

_NtDeleteValueKey NtDeleteValueKey = NULL;