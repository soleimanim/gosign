package macho

// CPU architecture headers
//
// A fat binary also known as a universal binary is a binary file that contains executable code for multiple architectures
const FAT_MAGIC uint32 = 0xcafebabe
const FAT_CIGAM uint32 = 0xbebafeca   // Fat binary header in reverse order (also known as Big endian)
const MH_MAGIC uint32 = 0xfeedface    // For 32 bit architectures
const MH_CIGAM uint32 = 0xcefaedfe    // For 32 bit architecture in reverse order
const MH_MAGIC_64 uint32 = 0xfeedfacf // For 64 bit architectures
const MH_CIGAM_64 uint32 = 0xcffaedfe // For 64 bit architectures in reverse order

// Load commands
const LC_SEGMENT uint32 = 0x00000001
const LC_SYMTAB uint32 = 0x00000002
const LC_SYMSEG uint32 = 0x00000003
const LC_THREAD uint32 = 0x00000004
const LC_UNIXTHREAD uint32 = 0x00000005
const LC_LOADFVMLIB uint32 = 0x00000006
const LC_IDFVMLIB uint32 = 0x00000007
const LC_IDENT uint32 = 0x00000008
const LC_FVMFILE uint32 = 0x00000009
const LC_PREPAGE uint32 = 0x0000000a
const LC_DYSYMTAB uint32 = 0x0000000b
const LC_LOAD_DYLIB uint32 = 0x0000000c
const LC_ID_DYLIB uint32 = 0x0000000d
const LC_LOAD_DYLINKER uint32 = 0x0000000e
const LC_ID_DYLINKER uint32 = 0x0000000f
const LC_PREBOUND_DYLIB uint32 = 0x00000010
const LC_ROUTINES uint32 = 0x00000011
const LC_SUB_FRAMEWORK uint32 = 0x00000012
const LC_SUB_UMBRELLA uint32 = 0x00000013
const LC_SUB_CLIENT uint32 = 0x00000014
const LC_SUB_LIBRARY uint32 = 0x00000015
const LC_TWOLEVEL_HINTS uint32 = 0x00000016
const LC_PREBIND_CKSUM uint32 = 0x00000017
const LC_LOAD_WEAK_DYLIB uint32 = 0x80000018
const LC_SEGMENT_64 uint32 = 0x00000019
const LC_ROUTINES_64 uint32 = 0x0000001A
const LC_UUID uint32 = 0x0000001B
const LC_RPATH uint32 = 0x8000001C
const LC_CODE_SIGNATURE uint32 = 0x0000001D
const LC_SEGMENT_SPLIT_INFO uint32 = 0x0000001E
const LC_REEXPORT_DYLIB uint32 = 0x8000001F
const LC_LAZY_LOAD_DYLIB uint32 = 0x00000020
const LC_ENCRYPTION_INFO uint32 = 0x00000021
const LC_DYLD_INFO uint32 = 0x00000022
const LC_DYLD_INFO_ONLY uint32 = 0x80000022
const LC_LOAD_UPWARD_DYLIB uint32 = 0x80000023
const LC_VERSION_MIN_MACOSX uint32 = 0x00000024
const LC_VERSION_MIN_IPHONEOS uint32 = 0x00000025
const LC_FUNCTION_STARTS uint32 = 0x00000026
const LC_DYLD_ENVIRONMENT uint32 = 0x00000027
const LC_MAIN uint32 = 0x80000028
const LC_DATA_IN_CODE uint32 = 0x00000029
const LC_SOURCE_VERSION uint32 = 0x0000002A
const LC_DYLIB_CODE_SIGN_DRS uint32 = 0x0000002B
const LC_ENCRYPTION_INFO_64 uint32 = 0x0000002C
const LC_LINKER_OPTION uint32 = 0x0000002D
const LC_LINKER_OPTIMIZATION_HINT uint32 = 0x0000002E
const LC_VERSION_MIN_TVOS uint32 = 0x0000002F
const LC_VERSION_MIN_WATCHOS uint32 = 0x00000030

const CSMAGIC_REQUIREMENT uint32 = 0xfade0c00               /* single Requirement blob */
const CSMAGIC_REQUIREMENTS uint32 = 0xfade0c01              /* Requirements vector (internal requirements) */
const CSMAGIC_CODEDIRECTORY uint32 = 0xfade0c02             /* CodeDirectory blob */
const CSMAGIC_EMBEDDED_SIGNATURE uint32 = 0xfade0cc0        /* embedded form of signature data */
const CSMAGIC_EMBEDDED_SIGNATURE_OLD uint32 = 0xfade0b02    /* XXX */
const CSMAGIC_EMBEDDED_ENTITLEMENTS uint32 = 0xfade7171     /* embedded entitlements */
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS uint32 = 0xfade7172 /* der format entitlements */
const CSMAGIC_DETACHED_SIGNATURE uint32 = 0xfade0cc1        /* multi-arch collection of embedded signatures */
const CSMAGIC_BLOBWRAPPER uint32 = 0xfade0b01               /* CMS Signature among other things */
const CS_SUPPORTSSCATTER uint32 = 0x20100
const CS_SUPPORTSTEAMID uint32 = 0x20200
const CS_SUPPORTSCODELIMIT64 uint32 = 0x20300
const CS_SUPPORTSEXECSEG uint32 = 0x20400
const CSSLOT_CODEDIRECTORY uint32 = 0 /* slot index for CodeDirectory */
const CSSLOT_INFOSLOT uint32 = 1
const CSSLOT_REQUIREMENTS uint32 = 2
const CSSLOT_RESOURCEDIR uint32 = 3
const CSSLOT_APPLICATION uint32 = 4
const CSSLOT_ENTITLEMENTS uint32 = 5

const CSSLOT_DER_ENTITLEMENTS uint32 = 7                                                                                  /* der format entitlement type */
const CSSLOT_ALTERNATE_CODEDIRECTORIES uint32 = 0x1000                                                                    /* first alternate CodeDirectory if any */
const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX uint32 = 5                                                                       /* max number of alternate CD slots */
const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT uint32 = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX /* one past the last */
const CSSLOT_SIGNATURESLOT uint32 = 0x10000                                                                               /* CMS Signature */
const CSSLOT_IDENTIFICATIONSLOT uint32 = 0x10001
const CSSLOT_TICKETSLOT uint32 = 0x10002
const CSTYPE_INDEX_REQUIREMENTS uint32 = 0x00000002 /* compat with amfi */
const CSTYPE_INDEX_ENTITLEMENTS uint32 = 0x00000005 /* compat with amfi */
const CS_HASHTYPE_SHA1 uint32 = 1
const CS_HASHTYPE_SHA256 uint32 = 2
const CS_HASHTYPE_SHA256_TRUNCATED uint32 = 3
const CS_HASHTYPE_SHA384 uint32 = 4
const CS_SHA1_LEN uint32 = 20
const CS_SHA256_LEN uint32 = 32
const CS_SHA256_TRUNCATED_LEN uint32 = 20
const CS_CDHASH_LEN uint32 = 20    /* always - larger hashes are truncated */
const CS_HASH_MAX_SIZE uint32 = 48 /* max size of the hash we'll support */
const CS_EXECSEG_MAIN_BINARY uint32 = 0x1
const CS_EXECSEG_ALLOW_UNSIGNED uint32 = 0x10

const CS_SIGNER_TYPE_UNKNOWN uint32 = 0
const CS_SIGNER_TYPE_LEGACYVPN uint32 = 5
