/* cacheinfo — report what this machine actually is.
 *
 * Exists so that performance claims name their hardware. "64-byte cache line"
 * is a statement about a machine, not a universal truth (SPEC §7.3), and every
 * benchmark result in this repo is meaningless without knowing where it ran.
 */
#include "pp/pp.h"
#include <stdio.h>

int main(void)
{
    size_t line = pp_hw_cacheline();

    printf("%s\n", pp_build_info());
    printf("\n");
    printf("  hardware cache line : %zu bytes\n", line);
    printf("  designed-for line   : %u bytes\n", PP_CACHELINE);

    if (line > PP_CACHELINE) {
        printf("  note                : this machine's line is larger than the\n"
               "                        design target, so a %u-byte struct fits\n"
               "                        comfortably. The design targets the\n"
               "                        stricter x86-64 bound on purpose.\n",
               PP_CACHELINE);
    } else if (line == PP_CACHELINE) {
        printf("  note                : design target matches this machine exactly.\n");
    } else if (line != 0) {
        printf("  note                : line is SMALLER than the design target;\n"
               "                        the one-line claim does NOT hold here.\n");
    }
    return 0;
}
