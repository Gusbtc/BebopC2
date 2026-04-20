/* beacon/include/resolve.h */
#pragma once
#include <windows.h>

/*
 * peb_get_module: find a loaded DLL by name (case-insensitive) via PEB walk.
 * Uses GS segment register (x64 only). Returns NULL if not found.
 */
HMODULE peb_get_module(const wchar_t *name);

/*
 * resolve_hash: walk the PE Export Address Table of hMod.
 * Returns the address of the function whose DJB2 name hash equals hash,
 * or NULL if not found.
 */
FARPROC resolve_hash(HMODULE hMod, DWORD hash);
