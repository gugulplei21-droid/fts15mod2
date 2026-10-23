#include "modmenu.h"
#include "dobby.h"
#include <jni.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <fstream>
#include <algorithm>

ModConfig g_cfg;

/* ======================================================================
 *  UTILIDADES
 * ====================================================================== */

uintptr_t GetModuleBase(const char* soName) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) { LOGE("No se pudo abrir /proc/self/maps"); return 0; }
    char line[512]; uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, soName) && strstr(line, "r-xp")) {
            base = (uintptr_t)strtoull(line, nullptr, 16);
            // Primer mapeo del módulo = base (si el .so tiene segmento r-- previo,
            // ajusta buscando la línea con offset 00000000).
            break;
        }
    }
    fclose(f);
    return base;
}

// Comprueba si una página está mapeada (mincore falla con ENOMEM si no).
static bool PageMapped(const void* p) {
    unsigned char v;
    uintptr_t page = (uintptr_t)p & ~(uintptr_t)(getpagesize() - 1);
    return mincore((void*)page, 1, &v) == 0;
}
bool IsReadable(const void* p, size_t len) {
    if (!p || (uintptr_t)p < 0x10000) return false;
    uintptr_t s = (uintptr_t)p & ~(uintptr_t)(getpagesize() - 1);
    uintptr_t e = ((uintptr_t)p + len - 1) & ~(uintptr_t)(getpagesize() - 1);
    for (uintptr_t a = s; a <= e; a += getpagesize())
        if (!PageMapped((void*)a)) return false;
    return true;
}
bool IsWritable(const void* p, size_t len) { return IsReadable(p, len); }

bool PatchBytes(uintptr_t addr, const void* data, size_t len) {
    if (!addr) return false;
    long ps = getpagesize();
    uintptr_t page = addr & ~(ps - 1);
    size_t span = (addr + len) - page;
    if (mprotect((void*)page, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect fallo en 0x%lx", (unsigned long)addr); return false;
    }
    memcpy((void*)addr, data, len);
    __builtin___clear_cache((char*)addr, (char*)(addr + len));
    mprotect((void*)page, span, PROT_READ | PROT_EXEC);
    return true;
}

// MOVZ Wd,#imm16  => 0x52800000 | imm16<<5 | Rd   (conserva el registro destino)
bool PatchMovImm32(uintptr_t addr, uint32_t newImm) {
    if (!addr || newImm > 0xFFFF) return false;
    uint32_t old = *(uint32_t*)addr;
    if ((old & 0x7F800000) != 0x52800000) { LOGE("0x%lx no es MOVZ Wn (0x%08x)", (unsigned long)addr, old); return false; }
    uint32_t ins = (old & 0xFFE0001F) | (newImm << 5);
    return PatchBytes(addr, &ins, 4);
}
// CMP Wn,#imm12 (SUBS WZR,Wn,#imm) => conserva Rn
bool PatchCmpImm32(uintptr_t addr, uint32_t newImm) {
    if (!addr || newImm > 0xFFF) return false;
    uint32_t old = *(uint32_t*)addr;
    if ((old & 0x7F80001F) != 0x7100001F) { LOGE("0x%lx no es CMP Wn,#imm (0x%08x)", (unsigned long)addr, old); return false; }
    uint32_t ins = (old & 0xFFC003FF) | (newImm << 10);
    return PatchBytes(addr, &ins, 4);
}

bool InstallHook(const char* name, uintptr_t offset, void* repl, void** orig) {
    if (offset == 0) { LOGW("[%s] offset = 0, hook omitido (rellena el marcador)", name); return false; }
    uintptr_t base = GetModuleBase(TARGET_LIB);
    if (!base) { LOGE("[%s] base de %s no encontrada", name, TARGET_LIB); return false; }
    void* target = (void*)(base + offset);
    if (!IsReadable(target, 4)) { LOGE("[%s] target %p invalido", name, target); return false; }
        int rc = ((int(*)(void*, void*, void**))&DobbyHook)(target, repl, orig);
    if (rc == 0 && *orig) LOGI("[%s] hook OK @ %p (base+0x%lx)", name, target, (unsigned long)offset);
    else LOGE("[%s] DobbyHook fallo rc=%d", name, rc);
    return rc == 0 && *orig;
}

/* ======================================================================
 *  1) VELOCIDAD DEL JUGADOR
 * ====================================================================== */
/* REEMPLAZAR_OFFSET_VELOCIDAD
 * En Ghidra busca la función que escribe la velocidad del jugador:
 *   - Candidatos: Player::SetVelocity / Player::Move / Player::UpdateMovement
 *   - Pistas: multiplica un vector por dt, usa constantes float de velocidad
 *     (p.ej. 5.0-10.0 m/s), referencias a "sprint"/"run", escribe 3 floats
 *     consecutivos en el objeto jugador (this+0x..).
 *   - Ajusta la firma de abajo a lo que veas en el decompilado. */
static constexpr uintptr_t OFFSET_PLAYER_SPEED = 0x0;

static void (*orig_PlayerSetVelocity)(void* self, Vec3* vel) = nullptr;
static void my_PlayerSetVelocity(void* self, Vec3* vel) {
    if (!orig_PlayerSetVelocity) return;
    if (!self || !IsReadable(vel, sizeof(Vec3))) { orig_PlayerSetVelocity(self, vel); return; }
    if (g_cfg.enabled && g_cfg.speedEnabled) {
        /* REEMPLAZAR_OFFSET_ISUSER (opcional): filtra solo al jugador humano
         * leyendo un flag en self+OFFSET, p.ej.:
         *   if (!IsReadable((char*)self+0x1A0,1) || !*((char*)self+0x1A0)) goto passthru; */
        float m = std::clamp(g_cfg.speedMultiplier.load(), 0.1f, 5.0f);
        Vec3 v{ vel->x * m, vel->y * m, vel->z };   // Z (vertical) intacto
        orig_PlayerSetVelocity(self, &v);
        return;
    }
    orig_PlayerSetVelocity(self, vel);
}
bool HookPlayerSpeed(uintptr_t) {
    return InstallHook("PlayerSpeed", OFFSET_PLAYER_SPEED,
                       (void*)my_PlayerSetVelocity, (void**)&orig_PlayerSetVelocity);
}

/* ======================================================================
 *  2) FISICA DEL BALON
 * ====================================================================== */
/* REEMPLAZAR_OFFSET_BALON
 * Busca la función de golpeo: Ball::Shoot / Ball::Kick / Ball::ApplyImpulse
 *   - Pistas: recibe un vector de fuerza/dirección y escribe la velocidad
 *     lineal del balón (this+0x..), suele llamarse desde el código de
 *     pase/tiro tras una animación de patada.
 * REEMPLAZAR_OFFSET_REBOTE
 * Busca la función que resuelve colisiones del balón (Ball::OnCollision /
 *   BounceOffGround) o el campo "restitution"/"bounciness" (float ~0.6-0.8)
 *   en la estructura del balón. Dos formas de modificarlo (elige UNA):
 *   A) hook a un setter SetRestitution(self, float)
 *   B) escribir el campo directamente en Shoot (OFFSET_FIELD_RESTITUTION). */
static constexpr uintptr_t OFFSET_BALL_SHOOT        = 0x0;
static constexpr uintptr_t OFFSET_BALL_SET_RESTIT   = 0x0;   // opcional (opción A)
static constexpr ptrdiff_t OFFSET_FIELD_RESTITUTION = 0x0;   // opcional (opción B)

static void (*orig_BallShoot)(void* self, Vec3* force) = nullptr;
static void my_BallShoot(void* self, Vec3* force) {
    if (!orig_BallShoot) return;
    if (!self || !IsReadable(force, sizeof(Vec3))) { orig_BallShoot(self, force); return; }
    if (g_cfg.enabled && g_cfg.ballEnabled) {
        float m = std::clamp(g_cfg.shotMultiplier.load(), 0.1f, 10.0f);
        Vec3 f{ force->x * m, force->y * m, force->z * m };
        orig_BallShoot(self, &f);
        float r = g_cfg.restitution;
        if (r >= 0.f && OFFSET_FIELD_RESTITUTION != 0) {
            float* fld = (float*)((char*)self + OFFSET_FIELD_RESTITUTION);
            if (IsWritable(fld, sizeof(float))) *fld = std::clamp(r, 0.0f, 2.0f);
        }
        return;
    }
    orig_BallShoot(self, force);
}

static void (*orig_SetRestitution)(void* self, float e) = nullptr;
static void my_SetRestitution(void* self, float e) {
    if (!orig_SetRestitution) return;
    float r = g_cfg.restitution;
    if (g_cfg.enabled && g_cfg.ballEnabled && r >= 0.f) e = std::clamp(r, 0.0f, 2.0f);
    orig_SetRestitution(self, e);
}

bool HookBallPhysics(uintptr_t) {
    bool a = InstallHook("BallShoot", OFFSET_BALL_SHOOT, (void*)my_BallShoot, (void**)&orig_BallShoot);
    bool b = InstallHook("BallRestitution", OFFSET_BALL_SET_RESTIT, (void*)my_SetRestitution, (void**)&orig_SetRestitution);
    return a || b;
}

/* ======================================================================
 *  3) ENTITY MANAGER: 22 -> 44
 * ====================================================================== */
/* REEMPLAZAR_OFFSET_ENTIDADES
 * Procedimiento en Ghidra:
 *  1. Busca la constante 22 / 0x16 (y 0x15, 0x17 en bucles <=/<) cerca de
 *     código que itera jugadores. Filtra por funciones que tocan arrays de
 *     punteros a Player (Team::players[11], Match::entities[22]).
 *  2. Identifica el tipo de almacenamiento:
 *     a) Array estático en .bss/.data  -> NO se puede crecer en sitio;
 *        hay que REDIRIGIR todas las referencias (adrp/add) o interceptar
 *        la función que lo inicializa y trabajar con un array nuevo.
 *     b) Array dentro del objeto EntityManager (this+0x..) -> el tamaño del
 *        objeto cambia; hay que parchear el tamaño en el operator new/
 *        constructor y los offsets de campos posteriores (muy frágil).
 *     c) Array en heap con capacidad (cap) -> el caso más sencillo: hook a
 *        Init/Reserve y sustituye el puntero + cap.
 *  3. Rellena los offsets de abajo.
 *
 * ESTRATEGIAS IMPLEMENTADAS:
 *  - Estrategia A (heap/cap): hook a EntityManager::Init, llama al original,
 *    reserva 44*stride con calloc, copia lo existente y reasigna puntero+cap.
 *  - Estrategia B (parches de constante): parcha `MOV Wn,#22` / `CMP Wn,#22`
 *    en cada sitio listado en kCountPatches.
 *  Normalmente hay que combinar ambas. */
static constexpr uintptr_t OFFSET_ENTITYMGR_INIT = 0x0;     // Estrategia A
static constexpr ptrdiff_t OFF_ARRAY_PTR  = 0x0;            // this+X -> Entity**
static constexpr ptrdiff_t OFF_ARRAY_CAP  = 0x0;            // this+X -> int capacity
static constexpr ptrdiff_t OFF_ARRAY_CNT  = 0x0;            // this+X -> int count
static constexpr size_t    ENTITY_SLOT_SZ = sizeof(void*);  // 8 si es array de punteros;
                                                            // sizeof(Entity) si es por valor

struct CountPatch { uintptr_t off; bool isCmp; };
static const CountPatch kCountPatches[] = {
    /* REEMPLAZAR_OFFSET_ENTIDADES: { 0x123456, false },  // MOV W8,#22 */
    /*                              { 0x1234AA, true  },  // CMP W9,#22 */
};

static void (*orig_EntityMgrInit)(void* self) = nullptr;
static void my_EntityMgrInit(void* self) {
    if (!orig_EntityMgrInit) return;
    orig_EntityMgrInit(self);
    if (!self || !(g_cfg.enabled && g_cfg.entitiesEnabled)) return;
    if (!OFF_ARRAY_PTR || !OFF_ARRAY_CAP) { LOGW("EntityMgr: offsets de campos sin rellenar"); return; }

    char* base = (char*)self;
    void**  pArr = (void**)(base + OFF_ARRAY_PTR);
    int*    pCap = (int*)(base + OFF_ARRAY_CAP);
    if (!IsReadable(pArr, 8) || !IsReadable(pCap, 4)) { LOGE("EntityMgr: campos ilegibles"); return; }

    int oldCap = *pCap, newCap = std::clamp(g_cfg.maxEntities.load(), 22, 64);
    if (oldCap <= 0 || oldCap > 256 || newCap <= oldCap) { LOGW("EntityMgr: cap=%d no valido/ya ampliado", oldCap); return; }

    void* oldArr = *pArr;
    void* newArr = calloc((size_t)newCap, ENTITY_SLOT_SZ);   // inicializado a 0 = slots libres
    if (!newArr) { LOGE("EntityMgr: calloc fallo"); return; }
    if (oldArr && IsReadable(oldArr, (size_t)oldCap * ENTITY_SLOT_SZ))
        memcpy(newArr, oldArr, (size_t)oldCap * ENTITY_SLOT_SZ);

    *pArr = newArr;      // no liberamos oldArr: puede ser estatico o tener otras referencias
    *pCap = newCap;
    LOGI("EntityMgr: %d -> %d slots (arr %p -> %p)", oldCap, newCap, oldArr, newArr);
}

bool HookEntityManager(uintptr_t base) {
    bool ok = InstallHook("EntityMgrInit", OFFSET_ENTITYMGR_INIT,
                          (void*)my_EntityMgrInit, (void**)&orig_EntityMgrInit);
    if (g_cfg.entitiesEnabled) {
        int n = std::clamp(g_cfg.maxEntities.load(), 22, 64);
        for (auto& p : kCountPatches) {
            uintptr_t a = base + p.off;
            bool r = p.isCmp ? PatchCmpImm32(a, n) : PatchMovImm32(a, n);
            LOGI("Patch constante @0x%lx -> %d : %s", (unsigned long)p.off, n, r ? "OK" : "FALLO");
            ok |= r;
        }
    }
    return ok;
}
/* NOTA: ampliar el array no basta. IA, equipos (2x11), formaciones, camara,
 * render, colisiones y spawn suelen asumir 22. Cada sitio hay que auditarlo. */

/* ======================================================================
 *  4) CONFIGURACION EN CALIENTE
 * ====================================================================== */
static std::string GetConfigPath() {
    char cmd[256] = {0};
    FILE* f = fopen("/proc/self/cmdline", "r");
    if (f) { fread(cmd, 1, sizeof(cmd) - 1, f); fclose(f); }
    std::string pkg = cmd[0] ? cmd : "unknown.package";
    return "/sdcard/Android/data/" + pkg + "/files/config.txt";
}

static void ApplyKV(const std::string& k, const std::string& v) {
    auto B = [&] { return v == "1" || v == "true"; };
    if      (k == "enabled")         g_cfg.enabled = B();
    else if (k == "speed_enabled")   g_cfg.speedEnabled = B();
    else if (k == "speed_mult")      g_cfg.speedMultiplier = strtof(v.c_str(), nullptr);
    else if (k == "ball_enabled")    g_cfg.ballEnabled = B();
    else if (k == "shot_mult")       g_cfg.shotMultiplier = strtof(v.c_str(), nullptr);
    else if (k == "restitution")     g_cfg.restitution = strtof(v.c_str(), nullptr);
    else if (k == "entities_enabled")g_cfg.entitiesEnabled = B();   // solo surte efecto al iniciar partida
    else if (k == "max_entities")    g_cfg.maxEntities = atoi(v.c_str());
    else LOGW("Config: clave desconocida '%s'", k.c_str());
}

static bool LoadConfig(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
        };
        trim(k); trim(v);
        ApplyKV(k, v);
    }
    LOGI("Config recargada: speed=%.2f shot=%.2f rest=%.2f ent=%d/%d",
         g_cfg.speedMultiplier.load(), g_cfg.shotMultiplier.load(), g_cfg.restitution.load(),
         (int)g_cfg.entitiesEnabled, g_cfg.maxEntities.load());
    return true;
}

void StartConfigWatcher() {
    std::thread([] {
        std::string path = GetConfigPath();
        LOGI("Config watcher: %s", path.c_str());
        time_t last = 0;
        for (;;) {
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                if (st.st_mtime != last) { last = st.st_mtime; LoadConfig(path); }
            } else if (last != -1) {
                LOGW("config.txt no existe; creando plantilla");
                std::ofstream o(path);
                if (o) o << "# ModMenuMaster\nenabled=1\nspeed_enabled=1\nspeed_mult=1.0\n"
                            "ball_enabled=1\nshot_mult=1.0\nrestitution=-1\n"
                            "entities_enabled=0\nmax_entities=44\n";
                last = -1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(750));
        }
    }).detach();
}

/* ======================================================================
 *  ENTRADA: JNI_OnLoad
 * ====================================================================== */
static void InitThread() {
    LOGI("=== ModMenuMaster iniciado (pid %d) ===", getpid());
    StartConfigWatcher();

    // Esperar a que la lib del juego esté mapeada (hasta ~30 s).
    uintptr_t base = 0;
    for (int i = 0; i < 300 && !(base = GetModuleBase(TARGET_LIB)); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (!base) { LOGE("No se encontró %s; abortando hooks", TARGET_LIB); return; }
    LOGI("Base de %s = 0x%lx", TARGET_LIB, (unsigned long)base);

    std::this_thread::sleep_for(std::chrono::seconds(2));  // dejar que termine su init

    LOGI("PlayerSpeed : %s", HookPlayerSpeed(base)  ? "OK" : "NO");
    LOGI("BallPhysics : %s", HookBallPhysics(base)  ? "OK" : "NO");
    LOGI("EntityMgr   : %s", HookEntityManager(base)? "OK" : "NO");
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) {
    LOGI("JNI_OnLoad");
    std::thread(InitThread).detach();   // no bloquear el hilo principal
    return JNI_VERSION_1_6;
}
