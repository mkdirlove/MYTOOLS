#include "hyperion.h"

/**
 * Jumps from the CoffHeader to the OptionalStandardHeader
 */
struct OptionalStandardHeader32* getOSH32(struct CoffHeader* coff_ptr){
        struct OptionalStandardHeader32* ret =
                (struct OptionalStandardHeader32*)
                ((char*) coff_ptr + sizeof(struct CoffHeader));
        return ret;
}

/**
 * Jumps from the OptionalStandardHeader to the OptionalWindowsHeader
 */
struct OptionalWindowsHeader32* getOWH32(struct OptionalStandardHeader32* os_ptr){
        return (struct OptionalWindowsHeader32*)
               (((char*) os_ptr) + sizeof(struct OptionalStandardHeader32));
}
