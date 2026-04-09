#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;

class Engine {
public:
    uint32_t magic;
    uint32_t flags;
    uint64_t counter;
    void *self;

    Engine();
    __attribute__((noinline)) void tick(uint32_t delta);
    __attribute__((noinline)) uint64_t snapshot() const;
};

Engine::Engine()
    : magic(0x454E474EU),
      flags(0x12U),
      counter(0x9000ULL),
      self(this) {}

void Engine::tick(uint32_t delta) {
    flags ^= delta;
    counter += delta;
}

uint64_t Engine::snapshot() const {
    return static_cast<uint64_t>(magic)
         ^ static_cast<uint64_t>(flags)
         ^ counter
         ^ reinterpret_cast<uintptr_t>(self);
}

static Engine g_engine;

__attribute__((noinline))
void drive_engine(void) {
    g_engine.tick(5U);
    sink ^= g_engine.snapshot();
}

__attribute__((noinline))
void inspect_engine(void) {
    sink ^= g_engine.magic;
    sink ^= g_engine.flags;
    sink ^= g_engine.counter;
    sink ^= reinterpret_cast<uintptr_t>(g_engine.self);
}

int main() {
    drive_engine();
    inspect_engine();
    std::printf("sink=%llx\n", static_cast<unsigned long long>(sink));
    return 0;
}
