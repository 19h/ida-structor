#include <stddef.h>
#include <stdint.h>

#define DECLARE_VTABLE(name) static void *name[] = { 0 }

DECLARE_VTABLE(off_1485D0AA8);
DECLARE_VTABLE(off_1485EF230);
DECLARE_VTABLE(off_14867BA00);
DECLARE_VTABLE(off_148AE9C68);
DECLARE_VTABLE(off_148AE9CB8);
DECLARE_VTABLE(off_148AE9D08);
DECLARE_VTABLE(off_148AE9D70);
DECLARE_VTABLE(off_148AE9DD0);
DECLARE_VTABLE(off_148AE9E30);
DECLARE_VTABLE(off_148AE9E90);
DECLARE_VTABLE(off_148AE9EE0);
DECLARE_VTABLE(off_148AE9F40);
DECLARE_VTABLE(off_148AE9F88);
DECLARE_VTABLE(vftable_spreadModifier);
DECLARE_VTABLE(vftable_aimModifier);
DECLARE_VTABLE(vftable_regenConsumerModifier);
DECLARE_VTABLE(vftable_salvageModifier);
DECLARE_VTABLE(off_148AEA0D8);

typedef struct SHandsRecoilCurveNoiseModiferRecovered {
    void *vfptr;
    float value0;
    float value1;
    float value2;
    int32_t pad0;
} SHandsRecoilCurveNoiseModiferRecovered;

typedef struct SRecoilCurveModifierBlockRecovered {
    void *vfptr;
    float value0;
    float value1;
    float value2;
    float value3;
    float value4;
    int32_t pad0;
    void *curve0;
    float value5;
    float value6;
    float value7;
    int32_t pad1;
    void *curve1;
    float value8;
    float value9;
    float value10;
    int32_t pad2;
    float value11;
    float value12;
    float value13;
    int32_t pad3;
    SHandsRecoilCurveNoiseModiferRecovered noise;
} SRecoilCurveModifierBlockRecovered;

typedef struct SAimRecoilModifierRecovered {
    void *vfptr;
    void *curve0;
    float value0;
    float value1;
    void *curve1;
    float value2;
    float value3;
    void *curve2;
    float value4;
    float value5;
    float value6;
    float value7;
    float value8;
    float value9;
    SRecoilCurveModifierBlockRecovered block;
} SAimRecoilModifierRecovered;

typedef struct SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered {
    void *vfptr;
    void *curve0;
    float value0;
    float value1;
    float value2;
    int32_t pad0;
    void *curve1;
    float value3;
    float value4;
    float value5;
    int32_t pad1;
    void *curve2;
    float value6;
    float value7;
    float value8;
    int32_t pad2;
} SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered;

typedef struct SXYZCurvesWithMaxValuesModiferRecovered {
    void *vfptr;
    float max0;
    float max1;
    float max2;
    int32_t pad0;
    void *curve0;
    float value0;
    float value1;
    float value2;
    int32_t pad1;
    void *curve1;
    float value3;
    float value4;
    float value5;
    int32_t pad2;
    SHandsRecoilCurveNoiseModiferRecovered noise;
} SXYZCurvesWithMaxValuesModiferRecovered;

typedef struct SActorProceduralHandsRecoilCurveModifiersDefRecovered {
    void *vfptr;
    float value0;
    int32_t pad0;
    SXYZCurvesWithMaxValuesModiferRecovered curves0;
    SXYZCurvesWithMaxValuesModiferRecovered curves1;
    float value1;
    float value2;
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered decay0;
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered decay1;
} SActorProceduralHandsRecoilCurveModifiersDefRecovered;

typedef struct SWeaponProceduralHeadRecoilCurveEntryRecovered {
    void *vfptr;
    void *curve0;
    float value0;
    float value1;
    float value2;
    int32_t pad0;
    void *curve1;
    float value3;
    float value4;
    float value5;
    int32_t pad1;
} SWeaponProceduralHeadRecoilCurveEntryRecovered;

typedef struct SWeaponProceduralHeadRecoilCurveModifierDefRecovered {
    void *vfptr;
    SWeaponProceduralHeadRecoilCurveEntryRecovered entry0;
    SWeaponProceduralHeadRecoilCurveEntryRecovered entry1;
    float value0;
    float value1;
    float value2;
    int32_t pad0;
} SWeaponProceduralHeadRecoilCurveModifierDefRecovered;

typedef struct SRecoilModifierRecovered {
    void *vfptr;
    float value0;
    float value1;
    float value2;
    float value3;
    float value4;
    float value5;
    float value6;
    float value7;
    float value8;
    float value9;
    float value10;
    float value11;
    float value12;
    int32_t pad0;
    void *curve0;
    float value13;
    float value14;
    float value15;
    int32_t pad1;
    SAimRecoilModifierRecovered aim;
    SActorProceduralHandsRecoilCurveModifiersDefRecovered hands;
    SWeaponProceduralHeadRecoilCurveModifierDefRecovered head;
} SRecoilModifierRecovered;

typedef struct SWeaponStatsModifierARecovered {
    void *vfptr;
    float spread0;
    float spread1;
    float spread2;
    float spread3;
    float spread4;
    int32_t spread5_bits;
} SWeaponStatsModifierARecovered;

typedef struct SWeaponStatsModifierBRecovered {
    void *vfptr;
    float aim0;
    float aim1;
    float aim2;
    uint8_t enabled;
    uint8_t pad0[3];
    float aim3;
    int32_t pad1;
} SWeaponStatsModifierBRecovered;

typedef struct SWeaponStatsModifierCRecovered {
    void *vfptr;
    float regen0;
    float regen1;
    float regen2;
    int32_t pad0;
} SWeaponStatsModifierCRecovered;

typedef struct SWeaponStatsModifierDRecovered {
    void *vfptr;
    float salvage0;
    float salvage1;
    float salvage2;
    uint8_t flag0;
    uint8_t flag1;
    uint8_t pad0[10];
} SWeaponStatsModifierDRecovered;

typedef struct SWeaponStatsRecovered {
    void *vfptr;
    int32_t value0;
    float value1;
    float value2;
    float value3;
    float value4;
    int32_t value5;
    int32_t value6;
    float value7;
    float value8;
    float value9;
    float value10;
    float value11;
    SRecoilModifierRecovered recoil;
    SWeaponStatsModifierARecovered spreadModifier;
    SWeaponStatsModifierBRecovered aimModifier;
    SWeaponStatsModifierCRecovered regenConsumerModifier;
    SWeaponStatsModifierDRecovered salvageModifier;
} SWeaponStatsRecovered;

typedef SWeaponStatsRecovered SWeaponStats;

_Static_assert(sizeof(SHandsRecoilCurveNoiseModiferRecovered) == 0x18, "noise size");
_Static_assert(sizeof(SRecoilCurveModifierBlockRecovered) == 0x78, "block size");
_Static_assert(sizeof(SAimRecoilModifierRecovered) == 0xC0, "aim recoil size");
_Static_assert(sizeof(SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered) == 0x50, "decay size");
_Static_assert(sizeof(SXYZCurvesWithMaxValuesModiferRecovered) == 0x60, "xyz size");
_Static_assert(sizeof(SActorProceduralHandsRecoilCurveModifiersDefRecovered) == 0x178, "hands size");
_Static_assert(sizeof(SWeaponProceduralHeadRecoilCurveEntryRecovered) == 0x38, "head entry size");
_Static_assert(sizeof(SWeaponProceduralHeadRecoilCurveModifierDefRecovered) == 0x88, "head mod size");
_Static_assert(sizeof(SRecoilModifierRecovered) == 0x318, "recoil size");
_Static_assert(sizeof(SWeaponStatsModifierARecovered) == 0x20, "spread size");
_Static_assert(sizeof(SWeaponStatsModifierBRecovered) == 0x20, "aim modifier size");
_Static_assert(sizeof(SWeaponStatsModifierCRecovered) == 0x18, "regen size");
_Static_assert(sizeof(SWeaponStatsModifierDRecovered) == 0x20, "salvage size");
_Static_assert(sizeof(SWeaponStatsRecovered) == 0x3C8, "weapon stats size");

_Static_assert(offsetof(SWeaponStatsRecovered, recoil) == 0x38, "recoil offset");
_Static_assert(offsetof(SWeaponStatsRecovered, spreadModifier) == 0x350, "spread offset");
_Static_assert(offsetof(SWeaponStatsRecovered, aimModifier) == 0x370, "aim offset");
_Static_assert(offsetof(SWeaponStatsRecovered, regenConsumerModifier) == 0x390, "regen offset");
_Static_assert(offsetof(SWeaponStatsRecovered, salvageModifier) == 0x3A8, "salvage offset");
_Static_assert(offsetof(SRecoilModifierRecovered, aim) == 0x58, "aim recoil offset");
_Static_assert(offsetof(SRecoilModifierRecovered, hands) == 0x118, "hands offset");
_Static_assert(offsetof(SRecoilModifierRecovered, head) == 0x290, "head offset");

static void *sub_140369E60(void *a1);
static void *sub_14037BF20(SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *a1);
static void *sub_14046E5B0(void **a1);
static void *sub_14275A5F0(SXYZCurvesWithMaxValuesModiferRecovered *a1);
static SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *
SActorProceduralHandsRecoilCurveDecayModifiersDef_CopyParams(
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *dst,
    const SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *src);
static SXYZCurvesWithMaxValuesModiferRecovered *SXYZCurvesWithMaxValuesModifer_CopyParams(
    SXYZCurvesWithMaxValuesModiferRecovered *dst,
    const SXYZCurvesWithMaxValuesModiferRecovered *src);
static SHandsRecoilCurveNoiseModiferRecovered *
SHandsRecoilCurveNoiseModifer_Init(SHandsRecoilCurveNoiseModiferRecovered *this_);
static SHandsRecoilCurveNoiseModiferRecovered *
SHandsRecoilCurveNoiseModifer_Init_0(SHandsRecoilCurveNoiseModiferRecovered *this_);
static SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *
SActorProceduralHandsRecoilCurveDecayModifiersDef_Init(
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *this_);
static SWeaponProceduralHeadRecoilCurveEntryRecovered *
sub_145FD4610(SWeaponProceduralHeadRecoilCurveEntryRecovered *this_);
static SWeaponProceduralHeadRecoilCurveModifierDefRecovered *
SWeaponProceduralHeadRecoilCurveModifierDef_Init(
    SWeaponProceduralHeadRecoilCurveModifierDefRecovered *this_);
static SRecoilCurveModifierBlockRecovered *
sub_145FD2960(SRecoilCurveModifierBlockRecovered *this_);
static SXYZCurvesWithMaxValuesModiferRecovered *
SXYZCurvesWithMaxValuesModifer_Init(SXYZCurvesWithMaxValuesModiferRecovered *this_);
static SActorProceduralHandsRecoilCurveModifiersDefRecovered *
SActorProceduralHandsRecoilCurveModifiersDef_Init(
    SActorProceduralHandsRecoilCurveModifiersDefRecovered *this_);
static SAimRecoilModifierRecovered *SAimRecoilModifier_Init(SAimRecoilModifierRecovered *this_);
static SRecoilModifierRecovered *SRecoilModifier_Init(SRecoilModifierRecovered *this_);
static SWeaponStats *SWeaponStats_Init(SWeaponStats *this_);

/* 0x140369E60 - sub_140369E60 */
static void *sub_140369E60(void *a1) {
    *(void **)a1 = off_1485D0AA8;
    return a1;
}

/* 0x14037BF20 - sub_14037BF20 */
static void *sub_14037BF20(SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *a1) {
    a1->curve2 = off_1485D0AA8;
    a1->curve1 = off_1485D0AA8;
    a1->curve0 = off_1485D0AA8;
    a1->vfptr = off_1485D0AA8;
    return off_1485D0AA8;
}

/* 0x14046E5B0 - sub_14046E5B0 */
static void *sub_14046E5B0(void **a1) {
    *a1 = off_1485EF230;
    return a1;
}

/* 0x14275A5F0 - sub_14275A5F0 */
static void *sub_14275A5F0(SXYZCurvesWithMaxValuesModiferRecovered *a1) {
    a1->noise.vfptr = off_1485D0AA8;
    a1->curve1 = off_1485D0AA8;
    a1->curve0 = off_1485D0AA8;
    a1->vfptr = off_1485D0AA8;
    return off_1485D0AA8;
}

/* 0x143181DF0 - SActorProceduralHandsRecoilCurveDecayModifiersDef::CopyParams */
static SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *
SActorProceduralHandsRecoilCurveDecayModifiersDef_CopyParams(
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *dst,
    const SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *src) {
    dst->value0 = src->value0;
    dst->value1 = src->value1;
    dst->value2 = src->value2;
    dst->value3 = src->value3;
    dst->value4 = src->value4;
    dst->value5 = src->value5;
    dst->value6 = src->value6;
    dst->value7 = src->value7;
    dst->value8 = src->value8;
    return dst;
}

/* 0x1431833F0 - SXYZCurvesWithMaxValuesModifer::CopyParams */
static SXYZCurvesWithMaxValuesModiferRecovered *SXYZCurvesWithMaxValuesModifer_CopyParams(
    SXYZCurvesWithMaxValuesModiferRecovered *dst,
    const SXYZCurvesWithMaxValuesModiferRecovered *src) {
    dst->max0 = src->max0;
    dst->max1 = src->max1;
    dst->max2 = src->max2;
    dst->value0 = src->value0;
    dst->value1 = src->value1;
    dst->value2 = src->value2;
    dst->value3 = src->value3;
    dst->value4 = src->value4;
    dst->value5 = src->value5;
    dst->noise.value0 = src->noise.value0;
    dst->noise.value1 = src->noise.value1;
    dst->noise.value2 = src->noise.value2;
    return dst;
}

/* 0x145FD2AC0 - SHandsRecoilCurveNoiseModifer::Init */
static SHandsRecoilCurveNoiseModiferRecovered *
SHandsRecoilCurveNoiseModifer_Init(SHandsRecoilCurveNoiseModiferRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9DD0;
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    return this_;
}

/* 0x145FD45A0 - SHandsRecoilCurveNoiseModifer::Init_0 */
static SHandsRecoilCurveNoiseModiferRecovered *
SHandsRecoilCurveNoiseModifer_Init_0(SHandsRecoilCurveNoiseModiferRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9C68;
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    return this_;
}

/* 0x145FD2BD0 - SActorProceduralHandsRecoilCurveDecayModifiersDef::Init */
static SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *
SActorProceduralHandsRecoilCurveDecayModifiersDef_Init(
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9D08;
    sub_14046E5B0(&this_->curve0);
    sub_14046E5B0(&this_->curve1);
    sub_14046E5B0(&this_->curve2);
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value4 = 1.0f;
    this_->value5 = 1.0f;
    this_->value6 = 1.0f;
    this_->value7 = 1.0f;
    this_->value8 = 1.0f;
    return this_;
}

/* 0x145FD4610 - sub_145FD4610 */
static SWeaponProceduralHeadRecoilCurveEntryRecovered *
sub_145FD4610(SWeaponProceduralHeadRecoilCurveEntryRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9E90;
    sub_14046E5B0(&this_->curve0);
    sub_14046E5B0(&this_->curve1);
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value4 = 1.0f;
    this_->value5 = 1.0f;
    return this_;
}

/* 0x145FD5780 - SWeaponProceduralHeadRecoilCurveModifierDef::Init */
static SWeaponProceduralHeadRecoilCurveModifierDefRecovered *
SWeaponProceduralHeadRecoilCurveModifierDef_Init(
    SWeaponProceduralHeadRecoilCurveModifierDefRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9EE0;
    sub_145FD4610(&this_->entry0);
    sub_145FD4610(&this_->entry1);
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    return this_;
}

/* 0x145FD2960 - sub_145FD2960 */
static SRecoilCurveModifierBlockRecovered *
sub_145FD2960(SRecoilCurveModifierBlockRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9E30;
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value4 = 1.0f;
    sub_14046E5B0(&this_->curve0);
    sub_14046E5B0(&this_->curve1);
    this_->value11 = 1.0f;
    this_->value12 = 1.0f;
    this_->value13 = 1.0f;
    SHandsRecoilCurveNoiseModifer_Init(&this_->noise);
    this_->value5 = 1.0f;
    this_->value6 = 1.0f;
    this_->value7 = 1.0f;
    this_->value8 = 1.0f;
    this_->value9 = 1.0f;
    this_->value10 = 1.0f;
    return this_;
}

/* 0x145FD5A10 - SXYZCurvesWithMaxValuesModifer::Init */
static SXYZCurvesWithMaxValuesModiferRecovered *
SXYZCurvesWithMaxValuesModifer_Init(SXYZCurvesWithMaxValuesModiferRecovered *this_) {
    sub_140369E60(this_);
    this_->vfptr = off_148AE9CB8;
    this_->max0 = 1.0f;
    this_->max1 = 1.0f;
    this_->max2 = 1.0f;
    sub_14046E5B0(&this_->curve0);
    sub_14046E5B0(&this_->curve1);
    SHandsRecoilCurveNoiseModifer_Init_0(&this_->noise);
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value4 = 1.0f;
    this_->value5 = 1.0f;
    return this_;
}

/* 0x145FD2CE0 - SActorProceduralHandsRecoilCurveModifiersDef::Init */
static SActorProceduralHandsRecoilCurveModifiersDefRecovered *
SActorProceduralHandsRecoilCurveModifiersDef_Init(
    SActorProceduralHandsRecoilCurveModifiersDefRecovered *this_) {
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered v6;
    SActorProceduralHandsRecoilCurveDecayModifiersDefRecovered v7;
    SXYZCurvesWithMaxValuesModiferRecovered v8;
    SXYZCurvesWithMaxValuesModiferRecovered v9;

    sub_140369E60(this_);
    this_->vfptr = off_148AE9D70;
    this_->value0 = 1.0f;
    SXYZCurvesWithMaxValuesModifer_Init(&this_->curves0);
    SXYZCurvesWithMaxValuesModifer_Init(&this_->curves1);
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    SActorProceduralHandsRecoilCurveDecayModifiersDef_Init(&this_->decay0);
    SActorProceduralHandsRecoilCurveDecayModifiersDef_Init(&this_->decay1);

    /* The original routine re-inits stack temporaries, copies only params, then
       resets the temporary vtable/curve slots before returning. */
    SXYZCurvesWithMaxValuesModifer_CopyParams(&this_->curves0, SXYZCurvesWithMaxValuesModifer_Init(&v8));
    sub_14275A5F0(&v8);
    SXYZCurvesWithMaxValuesModifer_CopyParams(&this_->curves1, SXYZCurvesWithMaxValuesModifer_Init(&v9));
    sub_14275A5F0(&v9);

    SActorProceduralHandsRecoilCurveDecayModifiersDef_CopyParams(
        &this_->decay0,
        SActorProceduralHandsRecoilCurveDecayModifiersDef_Init(&v6));
    sub_14037BF20(&v6);
    SActorProceduralHandsRecoilCurveDecayModifiersDef_CopyParams(
        &this_->decay1,
        SActorProceduralHandsRecoilCurveDecayModifiersDef_Init(&v7));
    sub_14037BF20(&v7);
    return this_;
}

/* 0x143175900 - SAimRecoilModifier::Init */
static SAimRecoilModifierRecovered *SAimRecoilModifier_Init(SAimRecoilModifierRecovered *this_) {
    this_->value6 = 1.0f;
    this_->vfptr = off_148AE9F40;
    this_->value7 = 1.0f;
    this_->curve0 = off_14867BA00;
    this_->curve1 = off_14867BA00;
    this_->curve2 = off_14867BA00;
    this_->value8 = 1.0f;
    this_->value9 = 1.0f;
    sub_145FD2960(&this_->block);
    this_->value0 = 1.0f;
    this_->value1 = 1.0f;
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value4 = 1.0f;
    this_->value5 = 1.0f;
    return this_;
}

/* 0x14317BA10 - SRecoilModifier::Init */
static SRecoilModifierRecovered *SRecoilModifier_Init(SRecoilModifierRecovered *this_) {
    this_->value0 = 1.0f;
    this_->vfptr = off_148AE9F88;
    this_->value1 = 1.0f;
    this_->curve0 = off_1485EF230;
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value4 = 1.0f;
    this_->value5 = 1.0f;
    this_->value6 = 1.0f;
    this_->value7 = 1.0f;
    this_->value8 = 1.0f;
    this_->value9 = 1.0f;
    this_->value10 = 1.0f;
    this_->value11 = 1.0f;
    this_->value12 = 1.0f;
    SAimRecoilModifier_Init(&this_->aim);
    SActorProceduralHandsRecoilCurveModifiersDef_Init(&this_->hands);
    SWeaponProceduralHeadRecoilCurveModifierDef_Init(&this_->head);
    this_->value13 = 1.0f;
    this_->value14 = 1.0f;
    this_->value15 = 1.0f;
    return this_;
}

/* 0x14317D700 - SWeaponStats::Init */
static SWeaponStats *SWeaponStats_Init(SWeaponStats *this_) {
    this_->value1 = 1.0f;
    this_->value0 = 0;
    this_->vfptr = off_148AEA0D8;
    this_->value4 = 1.0f;
    this_->value5 = 0;
    this_->value6 = 0;
    /* The original code does not write value7, most padding, or salvage flags. */
    this_->value2 = 1.0f;
    this_->value3 = 1.0f;
    this_->value8 = 1.0f;
    this_->value9 = 1.0f;
    this_->value10 = 1.0f;
    this_->value11 = 1.0f;
    SRecoilModifier_Init(&this_->recoil);
    this_->spreadModifier.spread0 = 1.0f;
    this_->spreadModifier.vfptr = vftable_spreadModifier;
    this_->aimModifier.vfptr = vftable_aimModifier;
    this_->regenConsumerModifier.vfptr = vftable_regenConsumerModifier;
    this_->salvageModifier.vfptr = vftable_salvageModifier;
    this_->spreadModifier.spread1 = 1.0f;
    this_->spreadModifier.spread2 = 1.0f;
    this_->spreadModifier.spread3 = 1.0f;
    this_->spreadModifier.spread4 = 1.0f;
    this_->spreadModifier.spread5_bits = 0;
    this_->aimModifier.aim0 = 1.0f;
    this_->aimModifier.aim1 = 1.0f;
    this_->aimModifier.aim2 = 1.0f;
    this_->aimModifier.enabled = 0;
    this_->aimModifier.aim3 = 1.0f;
    this_->regenConsumerModifier.regen0 = 1.0f;
    this_->regenConsumerModifier.regen1 = 1.0f;
    this_->regenConsumerModifier.regen2 = 1.0f;
    this_->salvageModifier.salvage0 = 1.0f;
    this_->salvageModifier.salvage1 = 1.0f;
    this_->salvageModifier.salvage2 = 1.0f;
    this_->salvageModifier.pad0[2] = 0;
    this_->salvageModifier.pad0[3] = 0;
    return this_;
}

int main(void) {
    SWeaponStats stats;

    (void)SWeaponStats_Init(&stats);
    return 0;
}
