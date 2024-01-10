#pragma once

void SpawnAndPing(char* data, int size, BOOL x86);

void BlockDlls(char* buffer, int length);

void Execute(char* buffer, int length);

void RunAsUser(char* buffer, int length);

void RunSetParentPid(char* buffer, int length);

void RunUnderPid(char* buffer, int length);

void SpawnUnder(char* buffer, int length, BOOL x86);

void SpawnAsUser(char* buffer, int length, BOOL x86);

void SpawnSetTo(char* buffer, int length, BOOL x86);

void Spawn(char* data, int size, BOOL x86, BOOL ignoreToken);