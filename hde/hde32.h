/*
* Hacker Disassembler Engine 32
* Copyright (c) 2006-2009, Vyacheslav Patkov.
* All rights reserved.
*
* hde32.h: C/C++ header file
*
*/

#ifndef _HDE32_H_
#define _HDE32_H_

#include <cstdint>

#include "hdedefines.h"

#pragma pack(push,1)

typedef struct {
	uint8_t len;
	uint8_t p_rep;
	uint8_t p_lock;
	uint8_t p_seg;
	uint8_t p_66;
	uint8_t p_67;
	uint8_t opcode;
	uint8_t opcode2;
	uint8_t modrm;
	uint8_t modrm_mod;
	uint8_t modrm_reg;
	uint8_t modrm_rm;
	uint8_t sib;
	uint8_t sib_scale;
	uint8_t sib_index;
	uint8_t sib_base;
	union {
		uint8_t imm8;
		uint16_t imm16;
		uint32_t imm32;
	} imm;
	uint8_t imm_len;
	uint8_t imm_offset;
	union {
		uint8_t disp8;
		uint16_t disp16;
		uint32_t disp32;
	} disp;
	uint8_t disp_len;
	uint8_t disp_offset;
	uint32_t flags;
} hde32s;

#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

	/* __cdecl */
	unsigned int hde32_disasm(uint8_t *code, hde32s *hs);

#ifdef __cplusplus
}
#endif

#endif /* _HDE32_H_ */
