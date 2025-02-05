#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <cstring>
#include <fstream>
#include <windows.h>

class SHA1 {
private:
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];

    void transform(const uint8_t block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
        uint32_t w[80];

        for (int i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        for (int i = 16; i < 80; i++) {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
            w[i] = (w[i] << 1) | (w[i] >> 31);
        }

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

public:
    SHA1() {
        reset();
    }

    void reset() {
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
        count = 0;
    }

    void update(const void* data, size_t len) {
        const uint8_t* p = (const uint8_t*)data;
        size_t i = count % 64;
        count += len;

        while (len--) {
            buffer[i++] = *p++;
            if (i == 64) {
                transform(buffer);
                i = 0;
            }
        }
    }

    void final(uint8_t digest[20]) {
        size_t i = count % 64;
        buffer[i++] = 0x80;

        if (i > 56) {
            memset(buffer + i, 0, 64 - i);
            transform(buffer);
            i = 0;
        }

        memset(buffer + i, 0, 56 - i);
        count *= 8;
        for (i = 0; i < 8; i++) {
            buffer[56 + i] = (count >> (56 - i * 8)) & 0xFF;
        }
        transform(buffer);

        for (i = 0; i < 20; i++) {
            digest[i] = (state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF;
        }
    }
};

std::vector<uint8_t> hmacSha1(const std::string& key, const std::vector<uint8_t>& message) {
    const size_t blockSize = 64;
    std::vector<uint8_t> keyPad(blockSize, 0);

    if (key.length() > blockSize) {
        SHA1 sha1;
        sha1.update(key.data(), key.length());
        std::vector<uint8_t> hash(20);
        sha1.final(hash.data());
        std::copy(hash.begin(), hash.begin() + 20, keyPad.begin());
    }
    else {
        std::copy(key.begin(), key.end(), keyPad.begin());
    }

    std::vector<uint8_t> innerPad(blockSize);
    std::vector<uint8_t> outerPad(blockSize);

    for (size_t i = 0; i < blockSize; i++) {
        innerPad[i] = keyPad[i] ^ 0x36;
        outerPad[i] = keyPad[i] ^ 0x5c;
    }

    SHA1 innerSha1;
    innerSha1.update(innerPad.data(), blockSize);
    innerSha1.update(message.data(), message.size());
    std::vector<uint8_t> innerHash(20);
    innerSha1.final(innerHash.data());

    SHA1 outerSha1;
    outerSha1.update(outerPad.data(), blockSize);
    outerSha1.update(innerHash.data(), innerHash.size());
    std::vector<uint8_t> result(20);
    outerSha1.final(result.data());

    return result;
}

class TOTPGenerator {
private:
    std::string secret;
    int digits;
    int interval;
    bool debug;

    uint32_t getDynamicTruncation(const std::vector<uint8_t>& hmacResult) {
        int offset = hmacResult[19] & 0xf;
        return ((hmacResult[offset] & 0x7f) << 24) |
            ((hmacResult[offset + 1] & 0xff) << 16) |
            ((hmacResult[offset + 2] & 0xff) << 8) |
            (hmacResult[offset + 3] & 0xff);
    }

public:
    TOTPGenerator(const std::string& secretKey, int digitLength = 6, int timeInterval = 30, bool debugMode = false)
        : secret(secretKey), digits(digitLength), interval(timeInterval), debug(debugMode) {
    }

    std::string generateTOTP(time_t time = time(nullptr)) {
        uint64_t timeStep = time / interval;

        std::vector<uint8_t> timeBytes(8);
        for (int i = 7; i >= 0; i--) {
            timeBytes[i] = timeStep & 0xff;
            timeStep >>= 8;
        }

        auto hmacResult = hmacSha1(secret, timeBytes);
        uint32_t truncatedHash = getDynamicTruncation(hmacResult);
        uint32_t code = truncatedHash % static_cast<uint32_t>(std::pow(10, digits));

        if (debug) {
            std::cout << "\nDebug Information:" << std::endl;
            std::cout << "Current Time (UTC): " << time << std::endl;
            std::cout << "Time Step: " << timeStep << std::endl;
            std::cout << "Time Bytes: ";
            for (const auto& byte : timeBytes) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(byte) << " ";
            }
            std::cout << std::dec << std::endl;

            std::cout << "HMAC-SHA1: ";
            for (const auto& byte : hmacResult) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(byte) << " ";
            }
            std::cout << std::dec << std::endl;

            std::cout << "Truncated Hash: " << truncatedHash << std::endl;
            std::cout << "Final Code: " << code << std::endl;
        }

        std::stringstream ss;
        ss << std::setw(digits) << std::setfill('0') << code;
        return ss.str();
    }
};

void printUsage(const char* programName) {
    std::cout << "TOTP Generator (RFC 6238)\n\n"
        << "Usage: " << programName << " <options>\n\n"
        << "Options:\n"
        << "  --secret <key>     Secret key (required)\n"
        << "  --digits <num>     Number of digits (default: 6)\n"
        << "  --interval <sec>   Time interval in seconds (default: 30)\n"
        << "  --debug           Enable debug output\n\n"
        << "Example:\n"
        << "  " << programName << " --secret mysecret --digits 8 --interval 60 --debug\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string secret;
    int digits = 6;
    int interval = 30;
    bool debug = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--secret" && i + 1 < argc) {
            secret = argv[++i];
        }
        else if (arg == "--digits" && i + 1 < argc) {
            digits = std::stoi(argv[++i]);
        }
        else if (arg == "--interval" && i + 1 < argc) {
            interval = std::stoi(argv[++i]);
        }
        else if (arg == "--debug") {
            debug = true;
        }
        else if (arg == "--install") {
            std::ifstream ini("config.ini");
            if (!ini.is_open()) {
                std::cout << "Error: config.ini not found\n";
                return 1;
            }

            std::string name, publisher, version;
            std::string line;
            while (std::getline(ini, line)) {
                if (line.find("Name=") == 0) name = line.substr(5);
                if (line.find("Publisher=") == 0) publisher = line.substr(10);
                if (line.find("Version=") == 0) version = line.substr(8);
            }
            ini.close();

            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);

            HKEY hKey;
            std::string regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + name;
            RegCreateKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, NULL,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

            RegSetValueExA(hKey, "DisplayName", 0, REG_SZ,
                (BYTE*)name.c_str(), name.length() + 1);
            RegSetValueExA(hKey, "Publisher", 0, REG_SZ,
                (BYTE*)publisher.c_str(), publisher.length() + 1);
            RegSetValueExA(hKey, "DisplayVersion", 0, REG_SZ,
                (BYTE*)version.c_str(), version.length() + 1);
            RegSetValueExA(hKey, "InstallLocation", 0, REG_SZ,
                (BYTE*)path, strlen(path) + 1);
            RegSetValueExA(hKey, "UninstallString", 0, REG_SZ,
                (BYTE*)("\"" + std::string(path) + "\" --uninstall").c_str(),
                strlen(path) + 13);

            RegCloseKey(hKey);
            std::cout << "Installation completed\n";
            return 0;
        }
        else if (arg == "--uninstall") {
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);

            std::ifstream ini("config.ini");
            std::string name;
            std::string line;
            while (std::getline(ini, line)) {
                if (line.find("Name=") == 0) {
                    name = line.substr(5);
                    break;
                }
            }
            ini.close();

            std::string regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + name;
            RegDeleteKeyA(HKEY_LOCAL_MACHINE, regPath.c_str());
            std::cout << "Uninstallation completed\n";
            return 0;
        }
        else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }

    if (secret.empty()) {
        std::cout << "Error: Secret key is required\n\n";
        printUsage(argv[0]);
        return 1;
    }

    TOTPGenerator totp(secret, digits, interval, debug);
    std::cout << "TOTP: " << totp.generateTOTP() << std::endl;

    return 0;
}