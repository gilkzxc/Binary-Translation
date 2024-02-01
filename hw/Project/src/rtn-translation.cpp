/*########################################################################################################*/
// cd /nfs/iil/ptl/bt/ghaber1/pin/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples
// make
//  ../../../pin -t obj-intel64/rtn-translation.so -- ~/workdir/tst
/*########################################################################################################*/
/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* ===================================================================== */

/* ===================================================================== */
/*! @file
 * This probe pintool generates translated code of routines, places them in an allocated TC 
 * and patches the orginal code to jump to the translated routines.
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>

using namespace std;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

KNOB<BOOL>   KnobInst(KNOB_MODE_WRITEONCE, "pintool",
	"opt", "0", "Probe mode");
KNOB<BOOL>   KnobProf(KNOB_MODE_WRITEONCE, "pintool",
	"prof", "0", "JIT mode");
KNOB<BOOL>   KnobDebug(KNOB_MODE_WRITEONCE, "pintool",
	"debug", "0", "Print debug main messages");
KNOB<UINT64> KnobHeatCoeff(KNOB_MODE_WRITEONCE, "pintool",
	"heat_cold_coefficient", "1", "Sets reorder heat coefficient");
KNOB<size_t> KnobMaxNumTopRTN(KNOB_MODE_WRITEONCE, "pintool",
	"max_num_of_top_rtn", "20", "Sets number of routines to translate coefficient");
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream* out = 0;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;	
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int targ_map_entry;
} instr_map_t;


instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;


// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;

/*Project*/
const ADDRINT NO_DOMINATE_CALL = (ADDRINT)0, NO_DIRECT_CONTROL_FLOW = (ADDRINT)0;


/*
*	Class xed_ins_to_translate:
*		A wrapper class that contain an assembly decoded instruction.
*/
class xed_ins_to_translate {
public:
	ADDRINT addr;
	USIZE size;
	ADDRINT target_addr;
	xed_decoded_inst_t data;
	xed_category_enum_t category_enum;
	xed_ins_to_translate() : addr((ADDRINT)0), size(0), target_addr((ADDRINT)0) {
		xed_decoded_inst_zero_set_mode(&(data), &dstate);
	}
	/* Main constructor for decoded instructions. */
	xed_ins_to_translate(ADDRINT new_addr, USIZE new_size, xed_error_enum_t& xed_code) : addr(new_addr), size(new_size) {
		target_addr = (ADDRINT)0;
		xed_decoded_inst_zero_set_mode(&data, &dstate);
		xed_code = xed_decode(&data, reinterpret_cast<UINT8*>(addr), max_inst_len);
		if (xed_code == XED_ERROR_NONE) {
			category_enum = xed_decoded_inst_get_category(&data);
			if (xed_decoded_inst_get_branch_displacement_width(&data) > 0) { // there is a branch offset.
				target_addr = new_addr + xed_decoded_inst_get_length(&data) + xed_decoded_inst_get_branch_displacement(&data);
			}
		}
	}
	/* unconditonal jump decoded constructor: 
		The user must check output parameters and category_enum, before usage.
	*/
	xed_ins_to_translate(ADDRINT new_orig_addr, ADDRINT new_orig_target, xed_bool_t& convert_ok,
		xed_error_enum_t& xed_code) {
		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		xed_int32_t disp = (xed_int32_t)(new_orig_target - new_orig_addr);
		xed_encoder_instruction_t  enc_instr;

		xed_inst1(&enc_instr, dstate,
			XED_ICLASS_JMP, 64,
			xed_relbr(disp, 32));

		xed_encoder_request_t enc_req;

		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (convert_ok) {
			unsigned int new_size = 0;
			xed_code = xed_encode(&enc_req, enc_buf, max_inst_len, &new_size);
			if (xed_code == XED_ERROR_NONE) {
				xed_ins_to_translate* result = new xed_ins_to_translate();
				xed_code = xed_decode(&(result->data), enc_buf, max_inst_len);
				if (xed_code == XED_ERROR_NONE) {
					data = result->data;
					addr = new_orig_addr;
					size = xed_decoded_inst_get_length(&data);
					target_addr = new_orig_target;
					xed_category_enum_t test_category = xed_decoded_inst_get_category(&data);
					category_enum = (test_category == XED_CATEGORY_UNCOND_BR) ? test_category : XED_CATEGORY_INVALID;
				}
				else {
					cerr << "JUMP: Failed to decode." << endl;
				}
				delete result;
			}
			else {
				cerr << "JUMP: Failed to encode." << endl;
			}
		}
	}
	xed_ins_to_translate(const xed_ins_to_translate& obj) : addr(obj.addr), size(obj.size), target_addr(obj.target_addr),
		data(obj.data), category_enum(obj.category_enum) {}
	xed_ins_to_translate& operator= (const xed_ins_to_translate& obj) {
		if (this == &obj) {
			return *this;
		}
		addr = obj.addr;
		size = obj.size;
		target_addr = obj.target_addr;
		data = obj.data;
		category_enum = obj.category_enum;
		return *this;
	}
	/*
	*	revert_cond_jump:
	*		Takes an existing decoded instruction of a conditional branch and revert it.
	*/
	bool revert_cond_jump(xed_error_enum_t& xed_code) {
		if (this->category_enum != XED_CATEGORY_COND_BR) {
			xed_code = XED_ERROR_NONE;
			return false;
		}

		xed_decoded_inst_t xed_to_revert = this->data;
		xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xed_to_revert);
		if (iclass_enum == XED_ICLASS_JRCXZ) {
			xed_code = XED_ERROR_NONE;
			return false;    // do not revert JRCXZ
		}
		xed_iclass_enum_t 	retverted_iclass;
		switch (iclass_enum) {

		case XED_ICLASS_JB:
			retverted_iclass = XED_ICLASS_JNB;
			break;

		case XED_ICLASS_JBE:
			retverted_iclass = XED_ICLASS_JNBE;
			break;

		case XED_ICLASS_JL:
			retverted_iclass = XED_ICLASS_JNL;
			break;

		case XED_ICLASS_JLE:
			retverted_iclass = XED_ICLASS_JNLE;
			break;

		case XED_ICLASS_JNB:
			retverted_iclass = XED_ICLASS_JB;
			break;

		case XED_ICLASS_JNBE:
			retverted_iclass = XED_ICLASS_JBE;
			break;

		case XED_ICLASS_JNL:
			retverted_iclass = XED_ICLASS_JL;
			break;

		case XED_ICLASS_JNLE:
			retverted_iclass = XED_ICLASS_JLE;
			break;

		case XED_ICLASS_JNO:
			retverted_iclass = XED_ICLASS_JO;
			break;

		case XED_ICLASS_JNP:
			retverted_iclass = XED_ICLASS_JP;
			break;

		case XED_ICLASS_JNS:
			retverted_iclass = XED_ICLASS_JS;
			break;

		case XED_ICLASS_JNZ:
			retverted_iclass = XED_ICLASS_JZ;
			break;

		case XED_ICLASS_JO:
			retverted_iclass = XED_ICLASS_JNO;
			break;

		case XED_ICLASS_JP:
			retverted_iclass = XED_ICLASS_JNP;
			break;

		case XED_ICLASS_JS:
			retverted_iclass = XED_ICLASS_JNS;
			break;

		case XED_ICLASS_JZ:
			retverted_iclass = XED_ICLASS_JNZ;
			break;

		default:
			xed_code = XED_ERROR_NONE;
			return false;
		}

		// Converts the decoder request to a valid encoder request:
		xed_encoder_request_init_from_decode(&xed_to_revert);

		// set the reverted opcode;
		xed_encoder_request_set_iclass(&xed_to_revert, retverted_iclass);

		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		unsigned int new_size = 0;

		xed_error_enum_t xed_error = xed_encode(&xed_to_revert, enc_buf, max_inst_len, &new_size);
		if (xed_error != XED_ERROR_NONE) {
			xed_code = xed_error;
			return false;
		}
		xed_decoded_inst_t new_xedd;
		xed_decoded_inst_zero_set_mode(&new_xedd, &dstate);

		xed_error = xed_decode(&new_xedd, enc_buf, max_inst_len);
		if (xed_error != XED_ERROR_NONE) {
			xed_code = xed_error;
			return false;
		}
		xed_decoded_inst_zero_set_mode(&this->data, &dstate);
		this->data = new_xedd;
		this->size = xed_decoded_inst_get_length(&new_xedd);
		return true;
	}
	~xed_ins_to_translate() {}
};




/*
*	Class rtn:
*		For analysis in Profile collecting mode.
*		Holds all needed info for a routine.
*/
class rtn {
public:
	std::string name;
	UINT64 ins_count;
	UINT64 call_count;
	bool is_recursive;
	bool to_inline;
	ADDRINT tail_address;
	std::map<ADDRINT, UINT64> caller_map;
	rtn() :name(""), ins_count(0), call_count(0), is_recursive(false), to_inline(true), tail_address((ADDRINT)0) {}
	rtn(const std::string new_name) :name(new_name), ins_count(0), call_count(0), is_recursive(false), to_inline(true), tail_address((ADDRINT)0) {}
	bool isCallerExist(ADDRINT caller_address) {
		return (!(this->caller_map.find(caller_address) == this->caller_map.end()));
	}
	/* dominate_call:
	*	returns the address of the most calling call instruction, that calls this routine.
	*	Meaning, the hot call site from the function that itself is a hot call site.
	*	If there are no dominate callers, will return the releveant 0.
	*/
	ADDRINT dominate_call() {
		if (this->caller_map.empty()) {
			return NO_DOMINATE_CALL;
		}
		std::vector<std::pair<ADDRINT, UINT64>> vec;
		for (auto itr = this->caller_map.begin(); itr != this->caller_map.end(); ++itr) {
			vec.push_back(*itr);
		}
		sort(vec.begin(), vec.end(),
			[=](std::pair<ADDRINT, UINT64>& a, std::pair<ADDRINT, UINT64>& b) {return a.second > b.second; });
		for (size_t i = 1; i < vec.size(); i++) {
			if (vec[i].second == vec[0].second) {
				return NO_DOMINATE_CALL;
			}
		}
		return vec[0].first;
	}
	void do_not_inline() {
		if (this->to_inline) {
			this->to_inline = false;
		}
	}
	~rtn() {}
};


/*
*	Class bbl:
*		For analysis in Profile collecting mode.
*		Holds all needed info for a basic block.
*/
class bbl {
public:
	ADDRINT tail_address;
	ADDRINT rtn_address;
	UINT64 count_total;
	UINT64 count_taken;
	ADDRINT jump_address;
	ADDRINT fall_address;
	bbl() :tail_address((ADDRINT)0), rtn_address((ADDRINT)0), count_total(0), count_taken(0),
		jump_address((ADDRINT)0), fall_address((ADDRINT)0) {}
	bbl(ADDRINT new_tail) :tail_address(new_tail), rtn_address((ADDRINT)0), count_total(0), count_taken(0),
		jump_address((ADDRINT)0), fall_address((ADDRINT)0) {}
	/* Handles multiple bbl with same tail. */
	bool merge(const bbl& obj) {
		if (this->rtn_address != obj.rtn_address || this->tail_address != obj.tail_address) {
			return false;
		}
		this->count_total += obj.count_total;
		this->count_taken += obj.count_taken;
		return true;
	}
	~bbl(){}

};

std::map<ADDRINT, rtn> rtn_map;
std::map<ADDRINT, bbl> bbl_map;
std::map<ADDRINT, UINT64> top_rtn;
bool isElementExistInMap(ADDRINT address, auto map) {
	return (!(map.find(address) == map.end()));
}
bool isRtnExist(ADDRINT rtn_address) {
	return isElementExistInMap(rtn_address, rtn_map);
}
bool isBblExist(ADDRINT bbl_address) {
	return isElementExistInMap(bbl_address, bbl_map);
}
bool isTopRtn(ADDRINT rtn_address) {
	return isElementExistInMap(rtn_address, top_rtn);
}


std::map<ADDRINT, std::vector<std::pair<ADDRINT, ADDRINT>>> inline_functions_candidates_for_top_rtn;
std::map<ADDRINT, std::vector<xed_ins_to_translate>> function_xedds_map;
std::map<ADDRINT, std::vector<std::pair<ADDRINT, ADDRINT>>> reorderd_rtn_map;
std::map<ADDRINT, ADDRINT> cond_br_address_to_end_of_fallthrough;
std::map<ADDRINT, ADDRINT> rtn_begin_cold_code;
bool isInlineCandidateExist(ADDRINT rtn_address, std::pair<ADDRINT, ADDRINT> call_site_and_candidate) {
	for (size_t i = 0; i < inline_functions_candidates_for_top_rtn[rtn_address].size(); i++) {
		if (inline_functions_candidates_for_top_rtn[rtn_address][i] == call_site_and_candidate) {
			return true;
		}
	}
	return false;
}
bool isInlineCandidateFunction(ADDRINT candidate_rtn_address) {
	for (auto itr = inline_functions_candidates_for_top_rtn.begin(); itr != inline_functions_candidates_for_top_rtn.end(); ++itr) {
		for (size_t i = 0; i < inline_functions_candidates_for_top_rtn[itr->first].size(); i++) {
			if (inline_functions_candidates_for_top_rtn[itr->first][i].second == candidate_rtn_address) {
				return true;
			}
		}
	}
	return false;
}



/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {				
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly 	

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);	

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{	
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);		
	}
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].targ_map_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }
 
	  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);	
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, ADDRINT orig_targ_addr = (ADDRINT)0)
{

	// copy orig instr to instr map:
	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
	
	xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = (orig_targ_addr != (ADDRINT)0) ? orig_targ_addr : (pc + xed_decoded_inst_get_length (xedd) + disp);
	}
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].targ_map_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;    	     

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}
	

    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}


/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {			    

		if (instr_map[i].orig_targ_addr == 0)
			continue;

		if (instr_map[i].hasNewTargAddr)
			continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
			   continue;
	
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true; 
	            instr_map[i].targ_map_entry = j;
                break;
			}
		}
	}
   
	return 0;
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) 
{
	//debug print:
	//dump_instr_map_entry(instr_map_entry);

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

	if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
		return 0;

	//cerr << "Memory Operands" << endl;
	bool isRipBase = false;
	xed_reg_enum_t base_reg = XED_REG_INVALID;
	xed_int64_t disp = 0;
	for(unsigned int i=0; i < memops ; i++)   {

		base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
		disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

		if (base_reg == XED_REG_RIP) {
			isRipBase = true;
			break;
		}
		
	}

	if (!isRipBase)
		return 0;

			
	//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
	xed_int64_t new_disp = 0;
	xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

	unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

	// modify rip displacement. use direct addressing mode:	
	new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
	xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

	//Set the memory displacement using a bit length 
	xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;
			
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);
	
	xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry); 
		return -1;
	}				

	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}
	
	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: " 
			  << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
		cerr << "category_enum: " << xed_category_enum_t2str(category_enum) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	// check for cases of direct jumps/calls back to the orginal target address:
	if (instr_map[instr_map_entry].targ_map_entry >= 0) {
		cerr << "ERROR: Invalid jump or call instruction" << endl;
		return -1;
	}

	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
				

	xed_encoder_instruction_t  enc_instr;

	ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
		               instr_map[instr_map_entry].new_ins_addr - 
					   xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

	if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}
   

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
	    dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

	// handle the case where the original instr size is different from new encoded instr:
	if (olen != xed_decoded_inst_get_length (&xedd)) {
		
		new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
	               instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			dump_instr_map_entry(instr_map_entry);
			return -1;
		}		
	}

	
	// debug prints:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry); 
	}
		
	instr_map[instr_map_entry].hasNewTargAddr = true;
	return olen;	
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) 
{					

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_int32_t  new_disp = 0;	
	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;


	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: unrecognized branch displacement" << endl;
		return -1;
	}

	// fix branches/calls to original targ addresses:
	if (instr_map[instr_map_entry].targ_map_entry < 0) {
		//cerr << "targ_map_entry: " << instr_map[instr_map_entry].targ_map_entry << endl;
	   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
	   return rc;
	}

	ADDRINT new_targ_addr;		
	new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
		
	new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

	xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

	// the max displacement size of loop instructions is 1 byte:
	xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
	if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
	  new_disp_byts = 1;
	}

	// the max displacement size of jecxz instructions is ???:
	xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
	if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
	  new_disp_byts = 1;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
	xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		char buf[2048];		
		xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
	    cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
  		return -1;
	}		

	new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

	new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
	
	xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}				

	//debug print of new instruction in tc:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}				


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;	

	do {
		
		size_diff = 0;

		if (KnobVerbose) {
			cerr << "starting a pass of fixing instructions displacements: " << endl;
		}

		for (int i=0; i < num_of_instr_map_entries; i++) {

			instr_map[i].new_ins_addr += size_diff;
				   
			int new_size = 0;

			// fix rip displacement:			
			new_size = fix_rip_displacement(i);
			if (new_size < 0)
				return -1;

			if (new_size > 0) { // this was a rip-based instruction which was fixed.

				if (instr_map[i].size != (unsigned int)new_size) {
				   size_diff += (new_size - instr_map[i].size); 					
				   instr_map[i].size = (unsigned int)new_size;								
				}

				continue;   
			}

			// check if it is a direct branch or a direct call instr:
			if (instr_map[i].orig_targ_addr == 0) {
				continue;  // not a direct branch or a direct call instr.
			}


			// fix instr displacement:			
			new_size = fix_direct_br_call_displacement(i);
			if (new_size < 0)
				return -1;

			if (instr_map[i].size != (unsigned int)new_size) {
			   size_diff += (new_size - instr_map[i].size);
			   instr_map[i].size = (unsigned int)new_size;
			}

		}  // end int i=0; i ..

	} while (size_diff != 0);

   return 0;
 }





/*
*	function reorder:
*	By using the profile from previous run, reorders the function's vector.
*/
std::vector<xed_ins_to_translate> reorder(std::vector<xed_ins_to_translate> translated_routine, std::vector<std::pair<ADDRINT, ADDRINT>> new_order)  {
	std::vector<xed_ins_to_translate> result;
	std::map<ADDRINT, size_t> back_edges;
	for (size_t i = 0; i < new_order.size(); i++) {
		for (auto itr = translated_routine.begin(); itr != translated_routine.end(); ++itr) {
			if (itr->addr >= new_order[i].first && itr->addr <= new_order[i].second) {
				if (itr->addr != new_order[i].second) {
					result.push_back(*itr);
				}
				else {
					if (itr->category_enum == XED_CATEGORY_COND_BR && (i < new_order.size() - 1 && itr != translated_routine.end() - 1)
						&& itr->target_addr == new_order[i + 1].first) {
						/* Fix cond jump. Cause the new order brings target to be FT.*/
						xed_ins_to_translate new_tail(*itr);
						xed_error_enum_t xed_error;
						if (new_tail.revert_cond_jump(xed_error)) {
							new_tail.target_addr = std::next(itr)->addr;
							result.push_back(new_tail);
							/* Adding a back edge to the end of the fall through.
							*/
							if(isElementExistInMap(itr->addr, cond_br_address_to_end_of_fallthrough)){
								back_edges[cond_br_address_to_end_of_fallthrough[itr->addr]] = i + 1;
							}
						}
						else if (xed_error != XED_ERROR_NONE) {
							/* Error handling in case of encoder/decoder failur. */
							cerr << "ENCODE ERROR at new_tail (Reorder): " << xed_error_enum_t2str(xed_error) << endl;
							result.clear();
							return result;
						}

					}
					else {
						result.push_back(*itr);
					}
				}
				if (isElementExistInMap(itr->addr, back_edges)) {
					xed_bool_t convert_ok;
					xed_error_enum_t xed_code;
					xed_ins_to_translate new_back_jump(itr->addr, new_order[back_edges[itr->addr]].first, convert_ok, xed_code);
					if (!convert_ok) {
						cerr << "conversion to encode request failed at new_jump. (Reorder)" << endl;
						result.clear();
						return result;
					}
					else if (xed_code != XED_ERROR_NONE) {
						cerr << "ENCODE ERROR at new_jump (Reorder): " << xed_error_enum_t2str(xed_code) << endl;
						result.clear();
						return result;
					}
					else if (new_back_jump.category_enum == XED_CATEGORY_INVALID) {
						cerr << "new_back_jump construction failed. (Reorder)" << endl;
						result.clear();
						return result;
					}
					else {
						result.push_back(new_back_jump);
					}
				}
			}
		}
	}
	return result;
}

/*
*	inline_functions:
*		By chosing the hot call sites given by the profile.
*		The function will inline candidates into the releveant call sites.
*		Also will fix the reordrer profile.
*/
int inline_functions(bool enable_inline) {
	if (!enable_inline) {
		return 0;
	}
	std::map<ADDRINT, ADDRINT> fix_target;
	for (auto itr = function_xedds_map.begin(); enable_inline && itr != function_xedds_map.end(); itr++) {
		std::vector<ADDRINT> functions_to_clear;
		std::vector<xed_ins_to_translate> new_function;
		if (inline_functions_candidates_for_top_rtn[itr->first].empty()) {
			continue;
		}
		for (auto it = itr->second.begin(); it != itr->second.end(); it++) {
			if (it->category_enum == XED_CATEGORY_CALL &&
				it->target_addr != NO_DIRECT_CONTROL_FLOW) {
				ADDRINT call_address = it->addr;
				ADDRINT target_address = it->target_addr;
				ADDRINT rtn_addr = itr->first;
				std::pair<ADDRINT, ADDRINT> inline_candidate(call_address, target_address);
				if (isElementExistInMap(target_address,function_xedds_map) && isInlineCandidateExist(rtn_addr, inline_candidate)) {
					if (KnobDebug) {
						std::cout << "In " << RTN_FindNameByAddress(rtn_addr) << " found call to : " << RTN_FindNameByAddress(target_address) << endl;
					}
					auto inline_it = function_xedds_map[target_address].begin();
					bool error_inline = false;
					for (; inline_it != function_xedds_map[target_address].end() - 1; inline_it++) {
						if (inline_it->category_enum == XED_CATEGORY_RET) {
							/* Any return instruction that is in the middle of the routine, is changed into a jump. */
							xed_bool_t convert_ok;
							xed_error_enum_t xed_code;
							xed_ins_to_translate new_jump(inline_it->addr, (it + 1)->addr, convert_ok, xed_code);
							if (!convert_ok) {
								cerr << "conversion to encode request failed at new_jump." << endl;
								error_inline = true;
								break;
							}
							else if (xed_code != XED_ERROR_NONE) {
								cerr << "ENCODE ERROR at new_jump: " << xed_error_enum_t2str(xed_code) << endl;
								error_inline = true;
								break;
							}
							else if (new_jump.category_enum == XED_CATEGORY_INVALID) {
								cerr << "new_jump construction failed." << endl;
								error_inline = true;
								break;
							}
							else {
								new_function.push_back(new_jump);
							}
						}
						else {
							new_function.push_back(*inline_it);
						}
					}
					if (error_inline) {
						enable_inline = false;
						functions_to_clear.clear();
						new_function.clear();
						return -1;
					}
					if (inline_it == function_xedds_map[target_address].end() - 1) {
						if (inline_it->category_enum != XED_CATEGORY_RET) {
							new_function.push_back(*inline_it);
						}
					}
					functions_to_clear.push_back(target_address);
					if (KnobDebug) {
						std::cout << "Done inserting xedds vector of " << RTN_FindNameByAddress(target_address) <<
							" into " << RTN_FindNameByAddress(rtn_addr) << endl;
					}
					if (!reorderd_rtn_map[itr->first].empty() && !reorderd_rtn_map[target_address].empty()) {
						/* Creating new reorder preparation for the new function created from the caller and callee. */
						std::vector<std::pair<ADDRINT, ADDRINT>> new_reorder;
						auto bbl_inline = reorderd_rtn_map[target_address].begin();
						for (auto bbl_limits = reorderd_rtn_map[itr->first].begin(); bbl_limits != reorderd_rtn_map[itr->first].end(); bbl_limits++) {
							if (bbl_limits->second == call_address) {
								std::pair<ADDRINT, ADDRINT> new_bbl(bbl_limits->first, bbl_limits->second - 1);
								new_reorder.push_back(new_bbl);
								/* Reorder the inline so it's cold parts are after the cold parts of the caller.
									Then only backwards jump are needed for the reorder.
								*/
								if (isElementExistInMap(target_address, rtn_begin_cold_code)) {
									for (; bbl_inline != reorderd_rtn_map[target_address].end() && bbl_inline->first != rtn_begin_cold_code[target_address]; bbl_inline++) {
										new_reorder.push_back(*bbl_inline);
									}
								}
							}
							else {
								new_reorder.push_back(*bbl_limits);
							}
						}
						/* Adding cold flow of the callee into the end of the caller cold flow. */
						for (; bbl_inline != reorderd_rtn_map[target_address].end(); bbl_inline++) {
							new_reorder.push_back(*bbl_inline);
						}
						if (KnobDebug) {
							std::cout << "New reorder:" << endl;
							for (auto bbl_limits = new_reorder.begin(); bbl_limits != new_reorder.end(); bbl_limits++) {
								std::cout << "0x" << std::hex << bbl_limits->first << ",0x" << std::hex << bbl_limits->second << std::endl;
							}
						}
						reorderd_rtn_map[itr->first] = new_reorder;
					}
				}
			}
			else {
				new_function.push_back(*it);
			}

		}
		if (!functions_to_clear.empty()) {
			itr->second.clear();
			itr->second = new_function;
			for (size_t i = 0; i < functions_to_clear.size(); i++) {
				function_xedds_map[functions_to_clear[i]].clear();
				reorderd_rtn_map[functions_to_clear[i]].clear();
			}
		}
	}
	return 0;
}

/* Inserting the decoded functions into the TC. */
int reorder_and_insert_translated_rtns_into_global_map(std::map<ADDRINT, USIZE> rtn_addr_to_rtn_size, bool enable_reorder) {
	int rc;
	for (auto itr = function_xedds_map.begin(); itr != function_xedds_map.end(); itr++) {
		if (!itr->second.empty()) {
			std::string rtn_name = RTN_FindNameByAddress(itr->first);
			std::vector<xed_ins_to_translate> reorderd;
			if (enable_reorder && !reorderd_rtn_map[itr->first].empty()) {
				if (KnobDebug) {
					std::cout << "Reorder " << rtn_name << ":" << endl;
				}
				reorderd = reorder(itr->second, reorderd_rtn_map[itr->first]);
				if (reorderd.empty()) {
					if (KnobDebug) {
						std::cout << "Reorder is empty." << endl;
					}
					continue;
				}
				if (KnobDebug) {
					char disasm_buf[2048];
					std::cout << "Original translated:" << endl;
					for (auto itt = itr->second.begin(); itt != itr->second.end(); itt++) {
						xed_format_context(XED_SYNTAX_INTEL, &(itt->data), disasm_buf, 2048, static_cast<UINT64>(itt->addr), 0, 0);
						std::cout << "0x" << hex << itt->addr << ": " << disasm_buf;
						if (itt->target_addr != 0) {
							std::cout << "     orig_targ: 0x" << hex << itt->target_addr << endl;
						}
						else {
							std::cout << endl;
						}
					}
					std::cout << "Reorderd translated:" << endl;
					for (auto itt = reorderd.begin(); itt != reorderd.end(); itt++) {
						xed_format_context(XED_SYNTAX_INTEL, &(itt->data), disasm_buf, 2048, static_cast<UINT64>(itt->addr), 0, 0);
						std::cout << "0x" << hex << itt->addr << ": " << disasm_buf;
						if (itt->target_addr != 0) {
							std::cout << "     new orig_targ: 0x" << hex << itt->target_addr << endl;
						}
						else {
							std::cout << endl;
						}
					}
				}
				itr->second.clear();
				itr->second = reorderd;
			}
			if (KnobDebug) {
				std::cout << "Inserting " << rtn_name << " into instr_map and translated_rtn." << endl;
			}
			translated_rtn[translated_rtn_num].rtn_addr = itr->first;
			translated_rtn[translated_rtn_num].rtn_size = rtn_addr_to_rtn_size[itr->first];
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;
			// debug print of routine name:
			if (KnobVerbose) {
				cerr << "rtn name: " << rtn_name << " : " << dec << translated_rtn_num << endl;
			}
			for (auto it = itr->second.begin(); it != itr->second.end(); it++) {
				if (it->target_addr != (ADDRINT)0) {
					/* Forced new orig_targ_addr */
					rc = add_new_instr_entry(&(it->data), it->addr, it->size, it->target_addr);
				}
				else {
					rc = add_new_instr_entry(&(it->data), it->addr, it->size);
				}
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					return rc;
				}
			}
			translated_rtn_num++;
			if (KnobDebug) {
				std::cout << "Done inserting." << endl;
			}
			
		}
	}
	return 0;
}

/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
int find_candidate_rtns_for_translation(IMG img)
{
	
	function_xedds_map.clear();
	std::map<ADDRINT, USIZE> rtn_addr_to_rtn_size;
	bool enable_inline = true, enable_reorder = true;
	// go over routines and check if they are candidates for translation and mark them for translation:

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;

		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{

			if (rtn == RTN_Invalid()) {
				cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
				continue;
			}
			ADDRINT rtn_addr = RTN_Address(rtn);
			/* reorder || key in inline || isInlineCandidateFunction*/
			if (!isElementExistInMap(rtn_addr, reorderd_rtn_map) && !isElementExistInMap(rtn_addr, inline_functions_candidates_for_top_rtn) && !isInlineCandidateFunction(rtn_addr)) {
				/* Function without profile for reorder, will not be translated. */
				continue;
			}
			//if (!isTopRtn(rtn_addr)) {
			//	continue;
			//}
			if (function_xedds_map.find(rtn_addr) != function_xedds_map.end()) {
				/* We translate only once. */
				continue;
			}
			if (KnobDebug) {
				std::cout << "Translating RTN: " << RTN_Name(rtn) << endl;
			}
			function_xedds_map[rtn_addr].clear();
			rtn_addr_to_rtn_size[rtn_addr] = RTN_Size(rtn);
			RTN_Open(rtn);
			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
				ADDRINT ins_addr = INS_Address(ins);
				USIZE ins_size = INS_Size(ins);
				xed_error_enum_t xed_error_code;
				xed_ins_to_translate new_xed(ins_addr, ins_size, xed_error_code);
				if (INS_IsDirectControlFlow(ins)) {
					new_xed.target_addr = INS_DirectControlFlowTargetAddress(ins);
				}
				//debug print of orig instruction:
				if (KnobVerbose) {
					cerr << "old instr: ";
					cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
					//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));				   			
				}
				if (xed_error_code != XED_ERROR_NONE) {
					cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << new_xed.addr << endl;
					return -1;
				}
				/* Adding new_xed to map of vector of xed */
				function_xedds_map[rtn_addr].push_back(new_xed);

			}
			// Close the RTN.
			RTN_Close(rtn);
			if (KnobDebug) {
				std::cout << "Decoding RTN: " << RTN_Name(rtn) << " was successful." << endl;
			}
		} // end for RTN..
	} // end for SEC...

	int rc = inline_functions(enable_inline);
	if (rc < 0) {
		return -1;
	}
	return reorder_and_insert_translated_rtns_into_global_map(rtn_addr_to_rtn_size, enable_reorder);
}


/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
	int cursor = 0;

	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }	  

	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() 
{
	// Commit the translated functions: 
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc
	
		if (translated_rtn[i].instr_map_entry >= 0) {
				    
			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {						

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:				
				if (rtn == RTN_Invalid()) {
					cerr << "committing rtN: Unknown";
				} else {
					cerr << "committing rtN: " << RTN_Name(rtn);
				}
				cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

						
				if (RTN_IsSafeForProbedReplacement(rtn)) {

					AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);							

					if (origFptr == NULL) {
						cerr << "RTN_ReplaceProbed failed.";
					} else {
						cerr << "RTN_ReplaceProbed succeeded. ";
					}
					cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
							<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;	

					dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);												
				}												
			}
		}
	}
}


/****************************/
/* allocate_and_init_memory */
/****************************/ 
int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
	
	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:		
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}
	
	tc = (char *)addr;
	return 0;
}
