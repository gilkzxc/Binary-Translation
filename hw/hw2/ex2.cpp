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
    UINT64 ins_count;
    UINT64 call_count;

    rtn() :name(""), ins_count(0), call_count(0) {}
    rtn(const std::string new_name) :name(new_name), ins_count(0), call_count(0) {}
    ~rtn() {}
};
class loop {
public:
    ADDRINT rtn_address;
    UINT64 countSeen;
    UINT64 countLoopInvoked;
    UINT64 meanTaken;
    UINT64 diffCount;
    
    loop() :rtn_address((ADDRINT)0), countSeen(0), countLoopInvoked(0), meanTaken(0), diffCount(0) {}
    loop(ADDRINT addr) :rtn_address(addr), countSeen(0), countLoopInvoked(0), meanTaken(0), diffCount(0) {}
    ~loop() {}
};


static std::map<ADDRINT, rtn> rtn_map;
static std::map<ADDRINT, loop> loop_map;
bool isRtnExist(ADDRINT rtn_address) {
    return (!(rtn_map.find(rtn_address) == rtn_map.end()));
}
bool isLoopExist(ADDRINT loop_address) {
    return (!(loop_map.find(loop_address) == loop_map.end()));
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
VOID docount_branch(ADDRINT target) {
    loop_map[target].countSeen++;
}

/* ===================================================================== */


VOID Instruction(INS ins, VOID* v) {
    RTN rtn_arg = INS_Rtn(ins);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        rtn rtn_obj(RTN_Name(rtn_arg));
        if (!isRtnExist(rtn_address)) {
            rtn_map.emplace(rtn_address, rtn_obj);
        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_ADDRINT, rtn_address, IARG_END);
        if (rtn_address == INS_Address(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_ADDRINT, rtn_address, IARG_END);
        }
        if (INS_IsDirectControlFlow(ins)) {
            ADDRINT myself = INS_Address(ins);
            ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
            if (target < myself) {
                loop loop_obj(rtn_address);
                if (!isLoopExist(target)) {
                    loop_map.emplace(target, loop_obj);
                }
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_branch, IARG_ADDRINT, target, IARG_END);
            }
        }
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    std::ofstream output_file("loop-count.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, loop>> vec;
    for (auto itr = loop_map.begin(); itr != loop_map.end(); ++itr) {
        vec.push_back(*itr);
    }
    sort(vec.begin(), vec.end(), [=](std::pair<ADDRINT, loop>& a, std::pair<ADDRINT, loop>& b) {return a.second.countSeen > b.second.countSeen; });
    for (size_t i = 0; i < vec.size(); i++) {
        ADDRINT rtn_addr = vec[i].second.rtn_address;
        output_file << "0x" << std::hex << vec[i].first << ", " << std::dec << vec[i].second.countSeen << ", "
            << vec[i].second.countLoopInvoked << ", " << vec[i].second.meanTaken << ", " << vec[i].second.diffCount
            << ", " << rtn_map[rtn_addr].name << ", 0x" << std::hex << rtn_addr << ", " << std::dec
            << rtn_map[rtn_addr].ins_count << ", " << rtn_map[rtn_addr].call_count << endl;
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
