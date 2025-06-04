/**
 * xbyak for the D programming language
 * Version: 0.7242
 * Date: 2025/04/30
 * See_Also:
 * Copyright: Copyright (c) 2007 MITSUNARI Shigeo, Copyright (c) 2019 deepprog
 * License: <http://opensource.org/licenses/BSD-3-Clause>BSD-3-Clause</a>.
 * Authors: herumi, deepprog
 */

module xbyak_util;

import core.stdc.stdio;
import core.stdc.stdlib;
import std.stdint;

version(X86)
{
    version = XBYAK32;
    version = XBYAK_INTEL_CPU_SPECIFIC;
}

version(X86_64)
{
    version = XBYAK64;
    version = XBYAK_INTEL_CPU_SPECIFIC;
}

version(Win64) version = XBYAK64_WIN;
version(XBYAK_ONLY_CLASS_CPU)
{
    enum ERR
    {
        NONE = 0,
        BAD_ADDRESSING,
        CODE_IS_TOO_BIG,
        BAD_SCALE,
        ESP_CANT_BE_INDEX,
        BAD_COMBINATION,
        BAD_SIZE_OF_REGISTER,
        IMM_IS_TOO_BIG,
        BAD_ALIGN,
        LABEL_IS_REDEFINED,
        LABEL_IS_TOO_FAR,
        LABEL_IS_NOT_FOUND,
        CODE_ISNOT_COPYABLE,
        BAD_PARAMETER,
        CANT_PROTECT,
        CANT_USE_64BIT_DISP,
        OFFSET_IS_TOO_BIG,
        MEM_SIZE_IS_NOT_SPECIFIED,
        BAD_MEM_SIZE,
        BAD_ST_COMBINATION,
        OVER_LOCAL_LABEL, // not used
        UNDER_LOCAL_LABEL,
        CANT_ALLOC,
        ONLY_T_NEAR_IS_SUPPORTED_IN_AUTO_GROW,
        BAD_PROTECT_MODE,
        BAD_PNUM,
        BAD_TNUM,
        BAD_VSIB_ADDRESSING,
        CANT_CONVERT,
        LABEL_ISNOT_SET_BY_L,
        LABEL_IS_ALREADY_SET_BY_L,
        BAD_LABEL_STR,
        MUNMAP,
        OPMASK_IS_ALREADY_SET,
        ROUNDING_IS_ALREADY_SET,
        K0_IS_INVALID,
        EVEX_IS_INVALID,
        SAE_IS_INVALID,
        ER_IS_INVALID,
        INVALID_BROADCAST,
        INVALID_OPMASK_WITH_MEMORY,
        INVALID_ZERO,
        INVALID_RIP_IN_AUTO_GROW,
        INVALID_MIB_ADDRESS,
        X2APIC_IS_NOT_SUPPORTED,
        NOT_SUPPORTED,
        SAME_REGS_ARE_INVALID,
        INVALID_NF,
        INVALID_ZU,
        CANT_USE_REX2,
        INVALID_DFV,
        INVALID_REG_IDX,
        BAD_ENCODING_MODE,
        CANT_USE_ABCDH,
        INTERNAL // Put it at last.
    }
    
    string XBYAK_THROW(ERR err)
    {
        return "return;";
    }
    string XBYAK_THROW_RET(ERR err, string r)
    {
        return "return " ~ r ~ ";";
    }
    string XBYAK_THROW_RET(string err, string r)
    {
        return "return " ~ r ~ ";";
    }
} else {
/**
    utility class and functions for Xbyak
    xbyak_util.Clock ; rdtsc timer
    xbyak_util.Cpu ; detect CPU
*/
import xbyak;
} // XBYAK_ONLY_CLASS_CPU

T local_max_(T)(T x, T y) { return x >= y ? x : y; }
T local_min_(T)(T x, T y) { return x < y ? x : y; }

enum CpuTopologyLevel
{
   SmtLevel = 1,
   CoreLevel = 2
}
alias SmtLevel = CpuTopologyLevel.SmtLevel;
alias CoreLevel = CpuTopologyLevel.CoreLevel;
alias IntelCpuTopologyLevel = CpuTopologyLevel; // for backward compatibility


class Cpu
{
public:
    struct Type
    {
        uint64_t L = 0;
        uint64_t H = 0;
    public:
        this(uint64_t L, uint64_t H = 0) 
        {
            this.L = L;
            this.H = H;
        }
        Type opOpAssign(string op:"&")(Type rhs)
        {
            this.L &= rhs.L;
            this.H &= rhs.H;
            return this;
        }
        Type opOpAssign(string op:"|")(Type rhs)
        {
            this.L |= rhs.L;
            this.H |= rhs.H;
            return this;
        }
        Type opBinary(string op:"&")(Type rhs) const
        {
            Type t = this;
            t &= rhs;
            return t;
        }
        Type opBinary(string op:"|")(Type rhs) const
        {
            Type t = this;
            t |= rhs;
            return t;
        }
        bool opEquals(Type rhs) const
        {
            return this.H == rhs.H && this.L == rhs.L;
        }
        // without explicit because backward compatilibity
        bool opCast() const { return (H | L) != 0; }
        uint64_t getL() const { return L; }
        uint64_t getH() const { return H; }
    }

private:
    Type type_;
    //system topology
    static const size_t maxTopologyLevels = 2;
    uint32_t[maxTopologyLevels] numCores_;

    static const uint32_t maxNumberCacheLevels = 10;
    uint32_t[maxNumberCacheLevels] dataCacheSize_;
    uint32_t[maxNumberCacheLevels] coresSharingDataCache_;
    uint32_t dataCacheLevels_;
    uint32_t avx10version_;

    uint32_t get32bitAsBE(const char* x) const
    {
        return x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24);
    }
    uint32_t mask(int n) const
    {
        return (1u << n) - 1;
    }
    // [EBX:ECX:EDX] == s?
    bool isEqualStr(uint32_t EBX, uint32_t ECX, uint32_t EDX, const char[12] s) const
    {
        return get32bitAsBE(&s[0]) == EBX && get32bitAsBE(&s[4]) == EDX && get32bitAsBE(&s[8]) == ECX;
    }
    uint32_t extractBit(uint32_t val, uint32_t base, uint32_t end) const
    {
        return (val >> base) & ((1u << (end + 1 - base)) - 1);
    }
    void setFamily()
    {
        uint32_t[4] data = [0, 0, 0, 0];
        getCpuid(1, data);
        stepping = extractBit(data[0], 0, 3);
        model = extractBit(data[0], 4, 7);
        family = extractBit(data[0], 8, 11);
        //type = extractBit(data[0], 12, 13);
        extModel = extractBit(data[0], 16, 19);
        extFamily = extractBit(data[0], 20, 27);
        if (family == 0x0f) {
            displayFamily = family + extFamily;
        } else {
            displayFamily = family;
        }
        if ((has(tINTEL) && family == 6) || family == 0x0f) {
            displayModel = (extModel << 4) + model;
        } else {
            displayModel = model;
        }
    }
    void setNumCores()
    {
        if (!has(tINTEL) && !has(tAMD)) return;

        uint32_t[4] data = [0, 0, 0, 0];
        getCpuid(0x0, data);
        if (data[0] >= 0xB) {
            // Check if "Extended Topology Enumeration" is implemented.
            getCpuidEx(0xB, 0, data);
            if (data[0] != 0 || data[1] != 0) {
                /*
                    if leaf 11 exists(x2APIC is supported),
                    we use it to get the number of smt cores and cores on socket

                    leaf 0xB can be zeroed-out by a hypervisor
                */
                for (uint32_t i = 0; i < maxTopologyLevels; i++) {
                    getCpuidEx(0xB, i, data);
                    CpuTopologyLevel level = cast(CpuTopologyLevel)extractBit(data[2], 8, 15);
                    if (level == SmtLevel || level == CoreLevel) {
                        numCores_[level - 1] = extractBit(data[1], 0, 15);
                    }
                }
                /*
                    Fallback values in case a hypervisor has the leaf zeroed-out.
                */
                numCores_[SmtLevel - 1] = local_max_(1u, numCores_[SmtLevel - 1]);
                numCores_[CoreLevel - 1] = local_max_(numCores_[SmtLevel - 1], numCores_[CoreLevel - 1]);
                return;
            }
        }
        // "Extended Topology Enumeration" is not supported.
        if (has(tAMD)) {
            /*
                AMD - Legacy Method
            */
            int physicalThreadCount = 0;
            getCpuid(0x1, data);
            int logicalProcessorCount = extractBit(data[1], 16, 23);
            int htt = extractBit(data[3], 28, 28); // Hyper-threading technology.
            getCpuid(0x80000000, data);
            uint32_t highestExtendedLeaf = data[0];
            if (highestExtendedLeaf >= 0x80000008) {
                getCpuid(0x80000008, data);
                physicalThreadCount = extractBit(data[2], 0, 7) + 1;
            }
            if (htt == 0) {
                numCores_[SmtLevel - 1] = 1;
                numCores_[CoreLevel - 1] = 1;
            } else if (physicalThreadCount > 1) {
                if ((displayFamily >= 0x17) && (highestExtendedLeaf >= 0x8000001E)) {
                    // Zen overreports its core count by a factor of two.
                    getCpuid(0x8000001E, data);
                    int threadsPerComputeUnit = extractBit(data[1], 8, 15) + 1;
                    physicalThreadCount /= threadsPerComputeUnit;
                }
                numCores_[SmtLevel - 1] = logicalProcessorCount / physicalThreadCount;
                numCores_[CoreLevel - 1] = logicalProcessorCount;
            } else {
                numCores_[SmtLevel - 1] = 1;
                numCores_[CoreLevel - 1] = logicalProcessorCount > 1 ? logicalProcessorCount : 2;
            }
        } else {
            /*
                Intel - Legacy Method
            */
            int physicalThreadCount = 0;
            getCpuid(0x1, data);
            int logicalProcessorCount = extractBit(data[1], 16, 23);
            int htt = extractBit(data[3], 28, 28); // Hyper-threading technology.
            getCpuid(0, data);
            if (data[0] >= 0x4) {
                getCpuid(0x4, data);
                physicalThreadCount = extractBit(data[0], 26, 31) + 1;
            }
            if (htt == 0) {
                numCores_[SmtLevel - 1] = 1;
                numCores_[CoreLevel - 1] = 1;
            } else if (physicalThreadCount > 1) {
                numCores_[SmtLevel - 1] = logicalProcessorCount / physicalThreadCount;
                numCores_[CoreLevel - 1] = logicalProcessorCount;
            } else {
                numCores_[SmtLevel - 1] = 1;
                numCores_[CoreLevel - 1] = logicalProcessorCount > 0 ? logicalProcessorCount : 1;
            }
        }
    }
    void setCacheHierarchy()
    {
        uint32_t[4] data = [0, 0, 0, 0];
        if (has(tAMD)) {
            getCpuid(0x80000000, data);
            if (data[0] >= 0x8000001D) {
                // For modern AMD CPUs.
                dataCacheLevels_ = 0;
                for (uint32_t subLeaf = 0; dataCacheLevels_ < maxNumberCacheLevels; subLeaf++) {
                    getCpuidEx(0x8000001D, subLeaf, data);
                    int cacheType = extractBit(data[0], 0, 4);
                    /*
                      cacheType
                        00h - Null; no more caches
                        01h - Data cache
                        02h - Instrution cache
                        03h - Unified cache
                        04h-1Fh - Reserved
                    */
                    if (cacheType == 0) break; // No more caches.
                    if (cacheType == 0x2) continue; // Skip instruction cache.
                    int fullyAssociative = extractBit(data[0], 9, 9);
                    int numSharingCache = extractBit(data[0], 14, 25) + 1;
                    int cacheNumWays = extractBit(data[1], 22, 31) + 1;
                    int cachePhysPartitions = extractBit(data[1], 12, 21) + 1;
                    int cacheLineSize = extractBit(data[1], 0, 11) + 1;
                    int cacheNumSets = data[2] + 1;
                    dataCacheSize_[dataCacheLevels_] =
                        cacheLineSize * cachePhysPartitions * cacheNumWays;
                    if (fullyAssociative == 0) {
                        dataCacheSize_[dataCacheLevels_] *= cacheNumSets;
                    }
                    if (subLeaf > 0) {
                        numSharingCache = local_min_(numSharingCache, cast(int)numCores_[1]);
                        numSharingCache /= local_max_(1u, coresSharingDataCache_[0]);
                    }
                    coresSharingDataCache_[dataCacheLevels_] = numSharingCache;
                    dataCacheLevels_ += 1;
                }
                coresSharingDataCache_[0] = local_min_(1u, coresSharingDataCache_[0]);
            } else if (data[0] >= 0x80000006) {
                // For legacy AMD CPUs, use leaf 0x80000005 for L1 cache
                // and 0x80000006 for L2 and L3 cache.
                dataCacheLevels_ = 1;
                getCpuid(0x80000005, data);
                int l1dc_size = extractBit(data[2], 24, 31);
                dataCacheSize_[0] = l1dc_size * 1024;
                coresSharingDataCache_[0] = 1;
                getCpuid(0x80000006, data);
                // L2 cache
                int l2_assoc = extractBit(data[2], 12, 15);
                if (l2_assoc > 0) {
                    dataCacheLevels_ = 2;
                    int l2_size = extractBit(data[2], 16, 31);
                    dataCacheSize_[1] = l2_size * 1024;
                    coresSharingDataCache_[1] = 1;
                }
                // L3 cache
                int l3_assoc = extractBit(data[3], 12, 15);
                if (l3_assoc > 0) {
                    dataCacheLevels_ = 3;
                    int l3_size = extractBit(data[3], 18, 31);
                    dataCacheSize_[2] = l3_size * 512 * 1024;
                    coresSharingDataCache_[2] = numCores_[1];
                }
            }
        } else if (has(tINTEL)) {
            // Use the "Deterministic Cache Parameters" leaf is supported.
            const uint32_t NO_CACHE = 0;
            const uint32_t DATA_CACHE = 1;
            //const uint32_t INSTRUCTION_CACHE = 2;
            const uint32_t UNIFIED_CACHE = 3;
            uint32_t smt_width = 0;
            uint32_t logical_cores = 0;

            smt_width = numCores_[0];
            logical_cores = numCores_[1];

            /*
                Assumptions:
                the first level of data cache is not shared (which is the
                case for every existing architecture) and use this to
                determine the SMT width for arch not supporting leaf 11.
                when leaf 4 reports a number of core less than numCores_
                on socket reported by leaf 11, then it is a correct number
                of cores not an upperbound.
            */
            for (int i = 0; dataCacheLevels_ < maxNumberCacheLevels; i++) {
                getCpuidEx(0x4, i, data);
                uint32_t cacheType = extractBit(data[0], 0, 4);
                if (cacheType == NO_CACHE) break;
                if (cacheType == DATA_CACHE || cacheType == UNIFIED_CACHE) {
                    uint32_t actual_logical_cores = extractBit(data[0], 14, 25) + 1;
                    if (logical_cores != 0) { // true only if leaf 0xB is supported and valid
                        actual_logical_cores = local_min_(actual_logical_cores, logical_cores);
                    }
                    assert(actual_logical_cores != 0);
                    dataCacheSize_[dataCacheLevels_] =
                        (extractBit(data[1], 22, 31) + 1)
                        * (extractBit(data[1], 12, 21) + 1)
                        * (extractBit(data[1], 0, 11) + 1)
                        * (data[2] + 1);
                    if (cacheType == DATA_CACHE && smt_width == 0) smt_width = actual_logical_cores;
                    assert(smt_width != 0);
                    coresSharingDataCache_[dataCacheLevels_] = local_max_(actual_logical_cores / smt_width, 1u);
                    dataCacheLevels_++;
                }
            }
        }
    }

public:
    int model;
    int family;
    int stepping;
    int extModel;
    int extFamily;
    int displayFamily;  // family + extFamily
    int displayModel;   // model + extModel

    uint32_t getNumCores(CpuTopologyLevel level) const
    {
        switch (level) {
            case SmtLevel: return numCores_[level - 1];
            case CoreLevel: return numCores_[level - 1] / numCores_[SmtLevel - 1];
            default: mixin(XBYAK_THROW_RET(ERR.X2APIC_IS_NOT_SUPPORTED, "0"));
        }
    }
    uint32_t getDataCacheLevels() const { return dataCacheLevels_; }
    uint32_t getCoresSharingDataCache(uint32_t i) const
    {
        if (i >= dataCacheLevels_) mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "0"));
        return coresSharingDataCache_[i];
    }
    uint32_t getDataCacheSize(uint32_t i) const
    {
        if (i >= dataCacheLevels_) mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "0"));
        return dataCacheSize_[i];
    }

    /*
        data[] = { eax, ebx, ecx, edx }
    */
    static void getCpuidEx(uint32_t eaxIn, uint32_t ecxIn, ref uint32_t[4] data)
    {
        uint32_t d0, d1, d2, d3;
        asm {
            mov EAX, eaxIn;
            mov ECX, ecxIn;
            cpuid;
            mov d0, EAX;
            mov d1, EBX;
            mov d2, ECX;
            mov d3, EDX;
        }
        data[0] = d0;
        data[1] = d1;
        data[2] = d2;
        data[3] = d3;
    }

    static void getCpuid(uint32_t eaxIn, ref uint32_t[4] data)
    {
        getCpuidEx(eaxIn, 0, data);
    }
    static uint64_t getXfeature()
    {
        uint32_t d, a;
        asm {
            mov ECX, 0;
            xgetbv;
            mov d, EDX;
            mov a, EAX;
        }
        return (cast(uint64_t) d << 32 | a);
    }

    enum tMMX                   = Type(1uL << 0, 0);
    enum tMMX2                  = Type(1uL << 1, 0);
    enum tCMOV                  = Type(1uL << 2, 0);
    enum tSSE                   = Type(1uL << 3, 0);
    enum tSSE2                  = Type(1uL << 4, 0);
    enum tSSE3                  = Type(1uL << 5, 0);
    enum tSSSE3                 = Type(1uL << 6, 0);
    enum tSSE41                 = Type(1uL << 7, 0);
    enum tSSE42                 = Type(1uL << 8, 0);
    enum tPOPCNT                = Type(1uL << 9, 0);
    enum tAESNI                 = Type(1uL << 10, 0);
    enum tAVX512_FP16           = Type(1uL << 11, 0);
    enum tOSXSAVE               = Type(1uL << 12, 0);
    enum tPCLMULQDQ             = Type(1uL << 13, 0);
    enum tAVX                   = Type(1uL << 14, 0);
    enum tFMA                   = Type(1uL << 15, 0);
    enum t3DN                   = Type(1uL << 16, 0);
    enum tE3DN                  = Type(1uL << 17, 0);
    enum tWAITPKG               = Type(1uL << 18, 0);
    enum tRDTSCP                = Type(1uL << 19, 0);
    enum tAVX2                  = Type(1uL << 20, 0);
    enum tBMI1                  = Type(1uL << 21, 0); // andn, bextr, blsi, blsmsk, blsr, tzcnt
    enum tBMI2                  = Type(1uL << 22, 0); // bzhi, mulx, pdep, pext, rorx, sarx, shlx, shrx
    enum tLZCNT                 = Type(1uL << 23, 0);
    enum tINTEL                 = Type(1uL << 24, 0);
    enum tAMD                   = Type(1uL << 25, 0);
    enum tENHANCED_REP          = Type(1uL << 26, 0); // enhanced rep movsb/stosb
    enum tRDRAND                = Type(1uL << 27, 0);
    enum tADX                   = Type(1uL << 28, 0); // adcx, adox
    enum tRDSEED                = Type(1uL << 29, 0); // rdseed
    enum tSMAP                  = Type(1uL << 30, 0); // stac
    enum tHLE                   = Type(1uL << 31, 0); // xacquire, xrelease, xtest
    enum tRTM                   = Type(1uL << 32, 0); // xbegin, xend, xabort
    enum tF16C                  = Type(1uL << 33, 0); // vcvtph2ps, vcvtps2ph
    enum tMOVBE                 = Type(1uL << 34, 0); // mobve
    enum tAVX512F               = Type(1uL << 35, 0);
    enum tAVX512DQ              = Type(1uL << 36, 0);
    enum tAVX512_IFMA           = Type(1uL << 37, 0);
    enum tAVX512IFMA            = Type(1uL << 37, 0); // = tAVX512_IFMA;
    enum tAVX512PF              = Type(1uL << 38, 0);
    enum tAVX512ER              = Type(1uL << 39, 0);
    enum tAVX512CD              = Type(1uL << 40, 0);
    enum tAVX512BW              = Type(1uL << 41, 0);
    enum tAVX512VL              = Type(1uL << 42, 0);
    enum tAVX512_VBMI           = Type(1uL << 43, 0);
    enum tAVX512VBMI            = Type(1uL << 43, 0); // = tAVX512_VBMI; // changed by Intel's manual
    enum tAVX512_4VNNIW         = Type(1uL << 44, 0);
    enum tAVX512_4FMAPS         = Type(1uL << 45, 0);
    enum tPREFETCHWT1           = Type(1uL << 46, 0);
    enum tPREFETCHW             = Type(1uL << 47, 0);
    enum tSHA                   = Type(1uL << 48, 0);
    enum tMPX                   = Type(1uL << 49, 0);
    enum tAVX512_VBMI2          = Type(1uL << 50, 0);
    enum tGFNI                  = Type(1uL << 51, 0);
    enum tVAES                  = Type(1uL << 52, 0);
    enum tVPCLMULQDQ            = Type(1uL << 53, 0);
    enum tAVX512_VNNI           = Type(1uL << 54, 0);
    enum tAVX512_BITALG         = Type(1uL << 55, 0);
    enum tAVX512_VPOPCNTDQ      = Type(1uL << 56, 0);
    enum tAVX512_BF16           = Type(1uL << 57, 0);
    enum tAVX512_VP2INTERSECT   = Type(1uL << 58, 0);
    enum tAMX_TILE              = Type(1uL << 59, 0);
    enum tAMX_INT8              = Type(1uL << 60, 0);
    enum tAMX_BF16              = Type(1uL << 61, 0);
    enum tAVX_VNNI              = Type(1uL << 62, 0);
    enum tCLFLUSHOPT            = Type(1uL << 63, 0);

    enum tCLDEMOTE              = Type(0, 1uL << (64 % 64));
    enum tMOVDIRI               = Type(0, 1uL << (65 % 64));
    enum tMOVDIR64B             = Type(0, 1uL << (66 % 64));
    enum tCLZERO                = Type(0, 1uL << (67 % 64)); // AMD Zen
    enum tAMX_FP16              = Type(0, 1uL << (68 % 64));
    enum tAVX_VNNI_INT8         = Type(0, 1uL << (69 % 64));
    enum tAVX_NE_CONVERT        = Type(0, 1uL << (70 % 64));
    enum tAVX_IFMA              = Type(0, 1uL << (71 % 64));
    enum tRAO_INT               = Type(0, 1uL << (72 % 64));
    enum tCMPCCXADD             = Type(0, 1uL << (73 % 64));
    enum tPREFETCHITI           = Type(0, 1uL << (74 % 64));
    enum tSERIALIZE             = Type(0, 1uL << (75 % 64));
    enum tUINTR                 = Type(0, 1uL << (76 % 64));
    enum tXSAVE                 = Type(0, 1uL << (77 % 64));
    enum tSHA512                = Type(0, 1uL << (78 % 64));
    enum tSM3                   = Type(0, 1uL << (79 % 64));
    enum tSM4                   = Type(0, 1uL << (80 % 64));
    enum tAVX_VNNI_INT16        = Type(0, 1uL << (81 % 64));
    enum tAPX_F                 = Type(0, 1uL << (82 % 64));
    enum tAVX10                 = Type(0, 1uL << (83 % 64));
    enum tAESKLE                = Type(0, 1uL << (84 % 64));
    enum tWIDE_KL               = Type(0, 1uL << (85 % 64));
    enum tKEYLOCKER             = Type(0, 1uL << (86 % 64));
    enum tKEYLOCKER_WIDE        = Type(0, 1uL << (87 % 64));
    enum tSSE4a                 = Type(0, 1uL << (88 % 64));
    enum tCLWB                  = Type(0, 1uL << (89 % 64));
    enum tTSXLDTRK              = Type(0, 1uL << (90 % 64));
    enum tAMX_TRANSPOSE         = Type(0, 1uL << (91 % 64));
    enum tAMX_TF32              = Type(0, 1uL << (92 % 64));
    enum tAMX_AVX512            = Type(0, 1uL << (93 % 64));
    enum tAMX_MOVRS             = Type(0, 1uL << (94 % 64));
    enum tAMX_FP8               = Type(0, 1uL << (95 % 64));

    this()
    {
        uint32_t[4] data = [0, 0, 0, 0];
        const uint32_t* EAX = cast(const uint32_t*)&data[0];
        const uint32_t* EBX = cast(const uint32_t*)&data[1];
        const uint32_t* ECX = cast(const uint32_t*)&data[2];
        const uint32_t* EDX = cast(const uint32_t*)&data[3];
        getCpuid(0, data);
        const uint32_t maxNum = *EAX;
        if (isEqualStr(*EBX, *ECX, *EDX, "AuthenticAMD")) {
            type_ |= tAMD;
            getCpuid(0x80000001, data);
            if (*EDX & (1U << 31)) {
                type_ |= t3DN;
                // 3DNow! implies support for PREFETCHW on AMD
                type_ |= tPREFETCHW;
            }

            if (*EDX & (1U << 29)) {
                // Long mode implies support for PREFETCHW on AMD
                type_ |= tPREFETCHW;
            }
        } else if (isEqualStr(*EBX, *ECX, *EDX, "GenuineIntel")) {
            type_ |= tINTEL;
        }

        // Extended flags information
        getCpuid(0x80000000, data);
        const uint32_t maxExtendedNum = *EAX;
        if (maxExtendedNum >= 0x80000001) {
            getCpuid(0x80000001, data);

            if (*ECX & (1U << 5)) type_ |= tLZCNT;
            if (*ECX & (1U << 6)) type_ |= tSSE4a;
            if (*ECX & (1U << 8)) type_ |= tPREFETCHW;
            if (*EDX & (1U << 15)) type_ |= tCMOV;
            if (*EDX & (1U << 22)) type_ |= tMMX2;
            if (*EDX & (1U << 27)) type_ |= tRDTSCP;
            if (*EDX & (1U << 30)) type_ |= tE3DN;
            if (*EDX & (1U << 31)) type_ |= t3DN;
        }

        if (maxExtendedNum >= 0x80000008) {
            getCpuid(0x80000008, data);
            if (*EBX & (1U << 0)) type_ |= tCLZERO;
        }

        getCpuid(1, data);
        if (*ECX & (1U << 0)) type_ |= tSSE3;
        if (*ECX & (1U << 1)) type_ |= tPCLMULQDQ;
        if (*ECX & (1U << 9)) type_ |= tSSSE3;
        if (*ECX & (1U << 19)) type_ |= tSSE41;
        if (*ECX & (1U << 20)) type_ |= tSSE42;
        if (*ECX & (1U << 22)) type_ |= tMOVBE;
        if (*ECX & (1U << 23)) type_ |= tPOPCNT;
        if (*ECX & (1U << 25)) type_ |= tAESNI;
        if (*ECX & (1U << 26)) type_ |= tXSAVE;
        if (*ECX & (1U << 27)) type_ |= tOSXSAVE;
        if (*ECX & (1U << 29)) type_ |= tF16C;
        if (*ECX & (1U << 30)) type_ |= tRDRAND;

        if (*EDX & (1U << 15)) type_ |= tCMOV;
        if (*EDX & (1U << 23)) type_ |= tMMX;
        if (*EDX & (1U << 25)) type_ |= tMMX2 | tSSE;
        if (*EDX & (1U << 26)) type_ |= tSSE2;

        if (type_ & tOSXSAVE) {
            // check XFEATURE_ENABLED_MASK[2:1] = '11b'
            uint64_t bv = getXfeature();
            if ((bv & 6) == 6) {
                if (*ECX & (1U << 12)) type_ |= tFMA;
                if (*ECX & (1U << 28)) type_ |= tAVX;
                
                if (((bv >> 5) & 7) == 7)
                {
                    getCpuidEx(7, 0, data);
                    if (*EBX & (1U << 16)) type_ |= tAVX512F;
                    if (type_ & tAVX512F) {
                        if (*EBX & (1U << 17)) type_ |= tAVX512DQ;
                        if (*EBX & (1U << 21)) type_ |= tAVX512_IFMA;
                        if (*EBX & (1U << 26)) type_ |= tAVX512PF;
                        if (*EBX & (1U << 27)) type_ |= tAVX512ER;
                        if (*EBX & (1U << 28)) type_ |= tAVX512CD;
                        if (*EBX & (1U << 30)) type_ |= tAVX512BW;
                        if (*EBX & (1U << 31)) type_ |= tAVX512VL;
                        if (*ECX & (1U << 1)) type_ |= tAVX512_VBMI;
                        if (*ECX & (1U << 6)) type_ |= tAVX512_VBMI2;
                        if (*ECX & (1U << 11)) type_ |= tAVX512_VNNI;
                        if (*ECX & (1U << 12)) type_ |= tAVX512_BITALG;
                        if (*ECX & (1U << 14)) type_ |= tAVX512_VPOPCNTDQ;
                        if (*EDX & (1U << 2)) type_ |= tAVX512_4VNNIW;
                        if (*EDX & (1U << 3)) type_ |= tAVX512_4FMAPS;
                        if (*EDX & (1U << 8)) type_ |= tAVX512_VP2INTERSECT;
                        if ((type_ & tAVX512BW) && (*EDX & (1U << 23))) type_ |= tAVX512_FP16;
                    }
                }
            }
        }
        if (maxNum >= 7) {
            getCpuidEx(7, 0, data);
            const uint32_t maxNumSubLeaves = *EAX;
            if (type_ & tAVX && (*EBX & (1U << 5))) type_ |= tAVX2;
            if (*EBX & (1U << 3)) type_ |= tBMI1;
            if (*EBX & (1U << 4)) type_ |= tHLE;
            if (*EBX & (1U << 8)) type_ |= tBMI2;
            if (*EBX & (1U << 9)) type_ |= tENHANCED_REP;
            if (*EBX & (1U << 11)) type_ |= tRTM;
            if (*EBX & (1U << 14)) type_ |= tMPX;
            if (*EBX & (1U << 18)) type_ |= tRDSEED;
            if (*EBX & (1U << 19)) type_ |= tADX;
            if (*EBX & (1U << 20)) type_ |= tSMAP;
            if (*EBX & (1U << 23)) type_ |= tCLFLUSHOPT;
            if (*EBX & (1U << 24)) type_ |= tCLWB;
            if (*EBX & (1U << 29)) type_ |= tSHA;
            if (*ECX & (1U << 0)) type_ |= tPREFETCHWT1;
            if (*ECX & (1U << 5)) type_ |= tWAITPKG;
            if (*ECX & (1U << 8)) type_ |= tGFNI;
            if (*ECX & (1U << 9)) type_ |= tVAES;
            if (*ECX & (1U << 10)) type_ |= tVPCLMULQDQ;
            if (*ECX & (1U << 23)) type_ |= tKEYLOCKER;
            if (*ECX & (1U << 25)) type_ |= tCLDEMOTE;
            if (*ECX & (1U << 27)) type_ |= tMOVDIRI;
            if (*ECX & (1U << 28)) type_ |= tMOVDIR64B;
            if (*EDX & (1U << 5)) type_ |= tUINTR;
            if (*EDX & (1U << 14)) type_ |= tSERIALIZE;
            if (*EDX & (1U << 16)) type_ |= tTSXLDTRK;
            if (*EDX & (1U << 22)) type_ |= tAMX_BF16;
            if (*EDX & (1U << 24)) type_ |= tAMX_TILE;
            if (*EDX & (1U << 25)) type_ |= tAMX_INT8;
            if (maxNumSubLeaves >= 1) {
                getCpuidEx(7, 1, data);
                if (*EAX & (1U << 0)) type_ |= tSHA512;
                if (*EAX & (1U << 1)) type_ |= tSM3;
                if (*EAX & (1U << 2)) type_ |= tSM4;
                if (*EAX & (1U << 3)) type_ |= tRAO_INT;
                if (*EAX & (1U << 4)) type_ |= tAVX_VNNI;
                if (type_ & tAVX512F) {
                    if (*EAX & (1U << 5)) type_ |= tAVX512_BF16;
                }
                if (*EAX & (1U << 7)) type_ |= tCMPCCXADD;
                if (*EAX & (1U << 21)) type_ |= tAMX_FP16;
                if (*EAX & (1U << 23)) type_ |= tAVX_IFMA;
                if (*EDX & (1U << 4)) type_ |= tAVX_VNNI_INT8;
                if (*EDX & (1U << 5)) type_ |= tAVX_NE_CONVERT;
                if (*EDX & (1U << 10)) type_ |= tAVX_VNNI_INT16;
                if (*EDX & (1U << 14)) type_ |= tPREFETCHITI;
                if (*EDX & (1U << 19)) type_ |= tAVX10;
                if (*EDX & (1U << 21)) type_ |= tAPX_F;

                getCpuidEx(0x1e, 1, data);
                if (*EAX & (1U << 4)) type_ |= tAMX_FP8;
                if (*EAX & (1U << 5)) type_ |= tAMX_TRANSPOSE;
                if (*EAX & (1U << 6)) type_ |= tAMX_TF32;
                if (*EAX & (1U << 7)) type_ |= tAMX_AVX512;
                if (*EAX & (1U << 8)) type_ |= tAMX_MOVRS;
            }
        }
        if (maxNum >= 0x19) {
            getCpuidEx(0x19, 0, data);
            if (*EBX & (1U << 0)) type_ |= tAESKLE;
            if (*EBX & (1U << 2)) type_ |= tWIDE_KL;
            if (type_ & (tKEYLOCKER|tAESKLE|tWIDE_KL)) type_ |= tKEYLOCKER_WIDE;
        }
        //if (has(tAVX10) && maxNum >= 0x24) {
        if ((tAVX & type_) == tAVX && maxNum >= 24) {
            getCpuidEx(0x24, 0, data);
            avx10version_ = *EBX & mask(7);
        }
        setFamily();
        setNumCores();
        setCacheHierarchy();
    }
    void putFamily() const
    {
version(XBYAK_ONLY_CLASS_CPU)
{}
else
{
        import core.stdc.stdio;
        printf("family=%d, model=%X, stepping=%d, extFamily=%d, extModel=%X\n",
            family, model, stepping, extFamily, extModel);
        printf("display:family=%X, model=%X\n", displayFamily, displayModel);
}
    }
    bool has(Type type) const
    {
        return (type & type_) == type;
    }
    int getAVX10version() const { return avx10version_; }
}

version(XBYAK_ONLY_CLASS_CPU)
{}
else
{
    struct Clock
    {
        public:
            static uint64_t getRdtsc()
            {
version(XBYAK_INTEL_CPU_SPECIFIC)
{
                asm {
                    naked;
                    rdtsc;
                    ret;
                }
} else {
                // TODO: Need another impl of Clock or rdtsc-equivalent for non-x86 cpu
                return 0;
}
            }
            void begin()
            {
                clock_ -= getRdtsc();
            }
            void end()
            {
                clock_ += getRdtsc();
                count_++;
            }
            int getCount() const { return count_; }
            uint64_t getClock() const { return clock_; }
            void clear() { count_ = 0; clock_ = 0; }
        private:
            uint64_t clock_ = 0;
            int count_ = 0;
    }

@("clock")
unittest
{
    import std.stdio;
    writeln("unittest clock");
    writeln("loop n : clock");
    Clock cl;
    const n1 = 123_456;
    cl.begin();
    for(int i=0; i<n1; i++){}
    cl.end();
    writeln(n1, " : ", cl.getClock());

    Clock cl2;
    const n2 = 1234_567;
    cl2.begin();
    for(int i=0; i<n2; i++){}
    cl2.end();
    writeln(n2, " : ", cl2.getClock());
    
    assert( cl.getClock() < cl2.getClock() );
}


version(XBYAK64)
{
    const int UseRCX = 1 << 6;
    const int UseRDX = 1 << 7;

    struct Pack
    {
        static const size_t maxTblNum = 15;
        Reg64[maxTblNum] tbl_;
        size_t n_;

    public:
        this(Reg64[] tbl, size_t n)
        {
            init(tbl, n);
        }
        this(ref Pack rhs)
        {
            n_ = rhs.n_;
            for (size_t i = 0; i < n_; i++) tbl_[i] = rhs.tbl_[i];
        }
        ref Pack opAssign(ref Pack rhs)
        {
            n_ = rhs.n_;
            for (size_t i = 0; i < n_; i++) tbl_[i] = rhs.tbl_[i];
            return this;
        }
        this(Reg64 t0)
        {
            n_ = 1;
            tbl_[0] = t0;
        }
        this(Reg64 t1, Reg64 t0)
        {
            n_ = 2;
            tbl_[0] = t0;
            tbl_[1] = t1;
        }
        this(Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 3;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
        }
        this(Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 4;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
        }
        this(Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 5;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
        }
        this(Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 6;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
        }
        this(Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 7;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
            tbl_[6] = t6;
        }
        this(Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 8;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
            tbl_[6] = t6;
            tbl_[7] = t7;
        }
        this(Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 9;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
            tbl_[6] = t6;
            tbl_[7] = t7;
            tbl_[8] = t8;
        }
        this(Reg64 t9, Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
        {
            n_ = 10;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
            tbl_[6] = t6;
            tbl_[7] = t7;
            tbl_[8] = t8;
            tbl_[9] = t9;
        }
        this(
            Reg64 ta,
            Reg64 t9, Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0
        )
        {
            n_ = 11;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
            tbl_[6] = t6;
            tbl_[7] = t7;
            tbl_[8] = t8;
            tbl_[9] = t9;
            tbl_[10] = ta;
        }
        this(
            Reg64 tb, 
            Reg64 ta,
            Reg64 t9, Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0
        )
        {
            n_ = 12;
            tbl_[0] = t0;
            tbl_[1] = t1;
            tbl_[2] = t2;
            tbl_[3] = t3;
            tbl_[4] = t4;
            tbl_[5] = t5;
            tbl_[6] = t6;
            tbl_[7] = t7;
            tbl_[8] = t8;
            tbl_[9] = t9;
            tbl_[10] = ta;
            tbl_[11] = tb;
        }

        ref Pack append(Reg64 t)
        {
            if (n_ == maxTblNum) {
                fprintf(stderr, "ERR Pack.can't append\n");
                mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "this"));
            }
            tbl_[n_++] = t;
            return this;
        }
        void init(Reg64[] tbl, size_t n)
        {
            if (n > maxTblNum) {
                fprintf(stderr, "ERR Pack::init bad n=%d\n", cast(int)n);
                mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
            }
            n_ = n;
            for (size_t i = 0; i < n; i++) {
                tbl_[i] = tbl[i];
            }
        }
        Reg64 opIndex(size_t n)
        {
            if (n >= n_) {
                fprintf(stderr, "ERR Pack bad n=%d(%d)\n", cast(int)n, cast(int)n_);
                mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "rax"));
            }
            return tbl_[n];
        }
        size_t size() const { return n_; }
        /*
            get tbl[pos, pos + num)
        */
        Pack sub(size_t pos, size_t num = cast(size_t)(-1))
        {
            if (num == cast(size_t)(-1)) num = n_ - pos;
            if (pos + num > n_) {
                fprintf(stderr, "ERR Pack.sub bad pos=%d, num=%d\n", cast(int)pos, cast(int)num);
                mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "Pack()"));
            }
            Pack pack;
            pack.n_ = num;
            for (size_t i = 0; i < num; i++) {
                pack.tbl_[i] = tbl_[pos + i];
            }
            return pack;
        }
        void put() const
        {
            for (size_t i = 0; i < n_; i++) {
                printf("%s ", tbl_[i].toString().ptr);
            }
            printf("\n");
        }
    }


    struct StackFrame
    {
version(XBYAK64_WIN)
{
        static const int noSaveNum = 6;
        static const int rcxPos = 0;
        static const int rdxPos = 1;
} else {
        static const int noSaveNum = 8;
        static const int rcxPos = 3;
        static const int rdxPos = 2;
}
        static const int maxRegNum = 14; // maxRegNum = 16 - rsp - rax
        CodeGenerator code_;
        int pNum_;
        int tNum_;
        bool useRcx_;
        bool useRdx_;
        int saveNum_;
        int P_;
        bool makeEpilog_;
        Reg64[4] pTbl_;
        Reg64[maxRegNum] tTbl_;
    public:
        Pack p; //= Pack();
        Pack t; //= Pack();

        /*
            make stack frame
            @param sf [in] this
            @param pNum [in] num of function parameter(0 <= pNum <= 4)
            @param tNum [in] num of temporary register(0 <= tNum, with UseRCX, UseRDX) #{pNum + tNum [+rcx] + [rdx]} <= 14
            @param stackSizeByte [in] local stack size
            @param makeEpilog [in] automatically call close() if true

            you can use
            rax
            gp0, ..., gp(pNum - 1)
            gt0, ..., gt(tNum-1)
            rcx if tNum & UseRCX
            rdx if tNum & UseRDX
            rsp[0..stackSizeByte - 1]
        */
        this(CodeGenerator code, int pNum, int tNum = 0, int stackSizeByte = 0, bool makeEpilog = true)
        {
            code_ = code;
            pNum_ = pNum;
            tNum_ = (tNum & ~(UseRCX | UseRDX));
            useRcx_ = ((tNum & UseRCX) != 0);
            useRdx_ = ((tNum & UseRDX) != 0);
            saveNum_ = 0;
            P_ = 0;
            makeEpilog_ = makeEpilog;
        
            if (pNum < 0 || pNum > 4) mixin(XBYAK_THROW(ERR.BAD_PNUM));
            const int allRegNum = pNum + tNum_ + (useRcx_ ? 1 : 0) + (useRdx_ ? 1 : 0);
            if (tNum_ < 0 || allRegNum > maxRegNum) mixin(XBYAK_THROW(ERR.BAD_TNUM));
            Reg64 _rsp = code.rsp;
            saveNum_ = local_max_(0, allRegNum - noSaveNum);
            int[] tbl = getOrderTbl(noSaveNum);
            for (int i = 0; i < saveNum_; i++) {
                code.push(new Reg64(tbl[i]));
            }

            P_ = (stackSizeByte + 7) / 8;
            if (P_ > 0 && (P_ & 1) == (saveNum_ & 1)) P_++; // (rsp % 16) == 8, then increment P_ for 16 byte alignment
            
            P_ *= 8;
            if (P_ > 0) code.sub(_rsp, P_);
            
            int pos = 0;
            for (int i = 0; i < pNum; i++) {
                pTbl_[i] = new Reg64(getRegIdx(pos));
            }
            
            for (int i = 0; i < tNum_; i++) {
                tTbl_[i] = new Reg64(getRegIdx(pos));
            }
            
            if (useRcx_ && rcxPos < pNum) code_.mov(code_.r10, code_.rcx);
            if (useRdx_ && rdxPos < pNum) code_.mov(code_.r11, code_.rdx);

            p.init(pTbl_, pNum);
            t.init(tTbl_, tNum_);
        }
        /*
            make epilog manually
            @param callRet [in] call ret() if true
        */
        void close(bool callRet = true)
        {
            Reg64 _rsp = code_.rsp;
            int[] tbl = getOrderTbl(noSaveNum);
            if (P_ > 0) code_.add(_rsp, P_);
            for (int i = 0; i < saveNum_; i++) {
                code_.pop(new Reg64(tbl[saveNum_ - 1 - i]));
            }

            if (callRet) code_.ret();
        }
        ~this()
        {
            if (!makeEpilog_) return;
            close();
        }

    private:
        int[] getOrderTbl(size_t n = 0)
        {
version(XBYAK64_WIN)
{
            static int[] tbl = [
                Operand.RCX, Operand.RDX, Operand.R8, Operand.R9, Operand.R10, Operand.R11, Operand.RDI, Operand.RSI,
                Operand.RBX, Operand.RBP, Operand.R12, Operand.R13, Operand.R14, Operand.R15
            ];
} else {
            static int[] tbl = [
                Operand.RDI, Operand.RSI, Operand.RDX, Operand.RCX, Operand.R8, Operand.R9, Operand.R10, Operand.R11,
                Operand.RBX, Operand.RBP, Operand.R12, Operand.R13, Operand.R14, Operand.R15
            ];
}
            return tbl[n..$];
        }

        int getRegIdx(ref int pos)
        {
            assert(pos < maxRegNum);
        
            int[] tbl = getOrderTbl();
            int r = tbl[pos++];
            if (useRcx_) {
                if (r == Operand.RCX) { return Operand.R10; }
                if (r == Operand.R10) { r = tbl[pos++]; }
            }
            if (useRdx_) {
                if (r == Operand.RDX) { return Operand.R11; }
                if (r == Operand.R11) { return tbl[pos++]; }
            }
            return r;
        }
    }
} // XBYAK_ONLY_CLASS_CPU

}
