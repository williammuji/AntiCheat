#include <gtest/gtest.h>

#include "hde/hde32.h"

TEST(HdeDisasmTest, DecodesJmpRel32)
{
    uint8_t code[] = {0xE9, 0x01, 0x00, 0x00, 0x00};
    hde32s hs = {};

    const unsigned int len = hde32_disasm(code, &hs);
    EXPECT_EQ(len, 5u);
    EXPECT_EQ(hs.len, 5);
    EXPECT_EQ(hs.opcode, 0xE9);
}

TEST(HdeDisasmTest, DecodesNop)
{
    uint8_t code[] = {0x90};
    hde32s hs = {};

    const unsigned int len = hde32_disasm(code, &hs);
    EXPECT_EQ(len, 1u);
    EXPECT_EQ(hs.len, 1);
    EXPECT_EQ(hs.opcode, 0x90);
}
