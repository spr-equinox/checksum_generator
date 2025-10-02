#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
#define SPDLOG_HEADER_ONLY

#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <future>
#include <xutility>
#include <Windows.h>
#include <spdlog/spdlog.h>
#include <BS_thread_pool.hpp>
#include <openssl/sha.h>
#include <atlbase.h>
#include <shobjidl.h>

#pragma warning(disable : 4996)

std::wstring folder_open_dialog()
{
    std::wstring ret;
    CComPtr<IFileOpenDialog> spFileOpenDialog;
    if (SUCCEEDED(spFileOpenDialog.CoCreateInstance(__uuidof(FileOpenDialog)))) {
        FILEOPENDIALOGOPTIONS options;
        if (SUCCEEDED(spFileOpenDialog->GetOptions(&options))) {
            spFileOpenDialog->SetOptions(options | FOS_PICKFOLDERS);
            if (SUCCEEDED(spFileOpenDialog->Show(nullptr))) {
                CComPtr<IShellItem> spResult;
                if (SUCCEEDED(spFileOpenDialog->GetResult(&spResult))) {
                    wchar_t* name;
                    if (SUCCEEDED(spResult->GetDisplayName(SIGDN_FILESYSPATH, &name))) {
                        ret = name;
                        CoTaskMemFree(name);
                    }
                }
            }
        }
    }
    return std::move(ret);
}

using std::filesystem::path;

BS::thread_pool *pool;

const size_t buf_size = 8ll * 1024 * 1024;

std::string generate_file_hash(const path& f) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);

    std::ifstream o(f, std::ios::binary);
    if (!o) 
        return std::string();
    char* buf = (char*)malloc(buf_size);
    if (!buf) 
        return o.close(), std::string();
    while (o.good()) {
        o.read(buf, buf_size);
        std::streamsize read_size = o.gcount();
        if (read_size > 0) {
            SHA256_Update(&sha256, buf, read_size);
        }
    }
    o.close(), free(buf);
    SHA256_Final(hash, &sha256);
    
    std::string result;
    result.reserve(SHA256_DIGEST_LENGTH << 1); // 保证足够的空间以存储十六进制字符
    for (unsigned char i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        // 直接将每个字节转换为两个十六进制字符并附加到结果字符串
        result.push_back("0123456789abcdef"[hash[i] >> 4]);   // 高四位
        result.push_back("0123456789abcdef"[hash[i] & 0x0F]); // 低四位
    }
    // spdlog::info(L"文件：{} SHA256：{}", f.generic_wstring(), std::wstring(result.begin(), result.end()));
    return result;
}

void generate_folder_hash(const path &p) {
    spdlog::info(L"处理文件夹：{}", p.generic_wstring());
    if (std::filesystem::exists(p / "checksum.sha256")) {
        spdlog::warn(L"文件夹：{} 已存在 checksum.sha256 跳过", p.generic_wstring());
        return;
    }
    std::list <std::pair<path, std::future<std::string>>> files;
    //std::list <std::pair<path, std::string>> files;
    for (const auto& it : std::filesystem::recursive_directory_iterator(p)) {
        if (!it.is_directory()) {
            auto now = it.path();
            files.emplace_back(now, pool->submit_task([now]() {
                return generate_file_hash(now);
            }));
            //files.emplace_back(now, [now](){
            //    return generate_file_hash(now);
            //}());
        }
    }
    pool->wait();
    std::ofstream o(p / "checksum.sha256");
    for (auto& [it, val] : files) {
        const std::string ret = val.get();
        if (ret.empty()) {
            spdlog::error(L"文件：{} SHA256计算失败", it.generic_wstring());
            continue;
        }
        o << ret << " " << reinterpret_cast<const char*>(it.lexically_relative(p).generic_u8string().c_str()) << "\n";
    }
    spdlog::info(L"文件夹：{} 处理完毕 共 {} 个文件", p.generic_wstring(), files.size());
}

int main(int argc, char* argv[])
{
    CoInitialize(nullptr);
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    int thread_count = 4;
    if (argc == 2) thread_count = atoi(argv[1]);
    try {
        pool = new BS::thread_pool(thread_count);
        spdlog::info(L"线程数：{}", thread_count);
    }
    catch (std::exception e){
        spdlog::critical("ERROR：{}", e.what());
        return 1;
    }

    std::wstring folder = folder_open_dialog();

    spdlog::info(L"选择文件夹：{}", folder);

    path root(std::move(folder));

    std::list<path> folders;

    for (const auto& it : std::filesystem::directory_iterator(root)) {
        if (it.is_directory()) {
            auto now = it.path();
            spdlog::info(L"找到子文件夹：{}", now.generic_wstring());
            folders.emplace_back(std::move(now));
        }
    }
    spdlog::info(L"开始处理");

    for (const auto& it : folders) {
        generate_folder_hash(it);
    }

    delete pool;
    CoUninitialize();
}

