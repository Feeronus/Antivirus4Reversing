﻿// header.h: включаемый файл для стандартных системных включаемых файлов
// или включаемые файлы для конкретного проекта
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
// Файлы заголовков Windows
#include <windows.h>
// Файлы заголовков среды выполнения C
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <shellapi.h>
#include <string>
#include <thread>
#include <format>
#include "SDDL.h"
#include <deque>
#include <mutex>
#include <condition_variable>
#include <Commdlg.h>
#include <shlobj_core.h>
#include <ctime>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <string>
#pragma comment(lib, "iphlpapi.lib")
#include "/Users/user/source/repos/SuperKeygen64/SuperKeygen64/base64-master/include/base64.hpp"
#include "/Users/user/source/repos/update-main/json-develop/single_include/nlohmann/json.hpp"
using json = nlohmann::json;
using namespace nlohmann::literals;
