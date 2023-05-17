/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

 /*! @file
  *  This file contains an ISA-portable PIN tool for counting dynamic instructions
  */

#include "pin.H"
#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
using std::cerr;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
class rtn {
public:
    std::string name;
    std::string image_name;
    ADDRINT image_address;
    UINT64 ins_count;
    UINT64 call_count;

    rtn() :name(""), image_name(""), image_address((ADDRINT)0),
        ins_count(0), call_count(0) {}
    rtn(const std::string new_name, const std::string new_image_name,
        ADDRINT new_image_address) :name(new_name), image_name(new_image_name), image_address(new_image_address),
        ins_count(0), call_count(0) {}
    ~rtn() {}
};



static std::map<ADDRINT, rtn> rtn_map;
bool isRtnExist(ADDRINT rtn_address) {
    return (!(rtn_map.find(rtn_address) == rtn_map.end()));
}
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

VOID docount_ins(ADDRINT rtn_address) {
    rtn_map[rtn_address].ins_count++;
}
VOID docount_rtn(ADDRINT rtn_address) {
    rtn_map[rtn_address].call_count++;
}

/* ===================================================================== */


VOID Instruction(INS ins, VOID* v) {
    RTN rtn_arg = INS_Rtn(ins);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG im = IMG_FindByAddress(rtn_address);
        if (IMG_Valid(im)) {
            rtn rtn_obj(RTN_Name(rtn_arg), IMG_Name(im), IMG_LowAddress(im));
            if (!isRtnExist(rtn_address)) {
                rtn_map.emplace(rtn_address, rtn_obj);
            }
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_ADDRINT, rtn_address, IARG_END);
            if (rtn_address == INS_Address(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_ADDRINT, rtn_address, IARG_END);
            }
        }
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    std::ofstream output_file("rtn-output.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, rtn>> vec;
    for (auto itr = rtn_map.begin(); itr != rtn_map.end(); ++itr) {
        vec.push_back(*itr);
    }
    sort(vec.begin(), vec.end(), [=](std::pair<ADDRINT, rtn>& a, std::pair<ADDRINT, rtn>& b) {return a.second.ins_count > b.second.ins_count; });
    for (size_t i = 0; i < vec.size(); i++) {
        output_file << vec[i].second.image_name << ", 0x" << std::hex << vec[i].second.image_address << ", " << vec[i].second.name << ", 0x"
            << std::hex << vec[i].first << ", " << std::dec << vec[i].second.ins_count << ", " << vec[i].second.call_count << endl;
    }
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
