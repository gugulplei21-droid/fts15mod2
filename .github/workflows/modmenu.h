#pragma once
#include <android/log.h>
#include <atomic>
#include <cstdint>
#include <cstddef>

#define TAG "ModMenuMaster"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* Nombre de la librería nativa del juego (la que contiene la lógica). */
/* REEMPLAZAR_NOMBRE_LIB: ej. "libfts.so" (míralo en lib/arm64-v8a/ del xapk) */
#define TARGET_LIB "libgame.so"

struct Vec3 { float x, y, z; };

// Configuración compartida entre el hilo de recarga y los hooks (lock-free).
struct ModConfig {
    std::atomic<bool>  enabled          {true};
    std::atomic<bool>  speedEnabled     {true};
    std::atomic<float> speedMultiplier  {1.0f};
    std::atomic<bool>  ballEnabled      {true};
    std::atomic<float> shotMultiplier   {1.0f};
    std::atomic<float> restitution      {-1.0f};  // <0 = no tocar
    std::atomic<bool>  entitiesEnabled  {false};
    std::atomic<int>   maxEntities      {44};
};
extern ModConfig g_cfg;

// Utilidades
uintptr_t GetModuleBase(const char* soName);
bool      IsReadable(const void* p, size_t len = sizeof(void*));
bool      IsWritable(const void* p, size_t len = sizeof(void*));
bool      PatchBytes(uintptr_t addr, const void* data, size_t len);
bool      PatchMovImm32(uintptr_t addr, uint32_t newImm);   // MOV Wn,#imm
bool      PatchCmpImm32(uintptr_t addr, uint32_t newImm);   // CMP Wn,#imm
bool      InstallHook(const char* name, uintptr_t offset, void* repl, void** orig);

// Subsistemas
bool HookPlayerSpeed(uintptr_t base);
bool HookBallPhysics(uintptr_t base);
bool HookEntityManager(uintptr_t base);
void StartConfigWatcher();
