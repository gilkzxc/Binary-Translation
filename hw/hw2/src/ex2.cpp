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
#include <vector>
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
    ADDRINT target_address;
    ADDRINT rtn_address;
    UINT64 totalCountSeen;
    UINT64 countLoopInvoked;
    std::vector<UINT64> countSeen;

    
    loop() :target_address((ADDRINT)0), rtn_address((ADDRINT)0), totalCountSeen(0), countLoopInvoked(0) {}
    loop(ADDRINT target_addr, ADDRINT rtn_addr) :target_address(target_addr), rtn_address(rtn_addr), totalCountSeen(0), countLoopInvoked(0) {}
    ~loop() {}
};

static std::map<ADDRINT, rtn> rtn_map;
static std::map<ADDRINT, loop> loop_map;
//static std::vector<ADDRINT> suspected_forward_cond_jump_as_loop;
bool isRtnExist(ADDRINT rtn_address) {
    return (!(rtn_map.find(rtn_address) == rtn_map.end()));
}
bool isLoopExist(ADDRINT loop_address) {
    return (!(loop_map.find(loop_address) == loop_map.end()));
}
//bool isJump
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
VOID docount_branch_iteration(ADDRINT loop_address) {
    loop_map[loop_address].countSeen[loop_map[loop_address].countLoopInvoked]++;
    loop_map[loop_address].totalCountSeen++;
}
VOID docount_branch_invocation(ADDRINT loop_address) {
    loop_map[loop_address].countLoopInvoked++;
    loop_map[loop_address].countSeen.push_back(0);
}
/* ===================================================================== */



VOID Routine(RTN rtn_arg, VOID* v) {
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        rtn rtn_obj(RTN_Name(rtn_arg));
        if (!isRtnExist(rtn_address)) {
            rtn_map.emplace(rtn_address, rtn_obj);
        }
        RTN_Open(rtn_arg);
        RTN_InsertCall(rtn_arg, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_ADDRINT, rtn_address, IARG_END);
        for (INS ins = RTN_InsHead(rtn_arg); INS_Valid(ins); ins = INS_Next(ins))
        {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_ADDRINT, rtn_address, IARG_END);
            if (INS_IsDirectControlFlow(ins) && !INS_IsCall(ins)) {
                ADDRINT myself = INS_Address(ins);
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
                if (INS_Category(ins) == XED_CATEGORY_COND_BR) {
                    if (target < myself) {
                        /* Handles 1st type loops, with single cond jump backwards. */
                        loop loop_obj(target, rtn_address);
                        if (!isLoopExist(myself)) {
                            loop_map.emplace(myself, loop_obj);
                            loop_map[myself].countSeen.push_back(0);
                        }
                        if (INS_IsValidForIpointAfter(ins)) {
                            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)docount_branch_invocation, IARG_ADDRINT, myself, IARG_END);
                        }
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_branch_iteration, IARG_ADDRINT, myself, IARG_END);
                    }
                    else if (target > myself) {
                        /* Handles 2nd type loops, with a single cond' jump forward
                            and a single uncond' jump backwards to the address of myself.
                        */
                        INS cond_jump = INS_Next(ins);
                        for (; INS_Valid(cond_jump); cond_jump = INS_Next(cond_jump)) {
                            if (INS_IsDirectControlFlow(cond_jump) && !INS_IsCall(cond_jump) && INS_Category(cond_jump) == XED_CATEGORY_UNCOND_BR 
                                && INS_DirectControlFlowTargetAddress(cond_jump) <= myself){
                                break;
                            }
                        }
                        if (INS_Valid(cond_jump)) {
                            if(INS_IsDirectControlFlow(cond_jump) && !INS_IsCall(cond_jump)){
                                ADDRINT target_back = INS_DirectControlFlowTargetAddress(cond_jump);
                                loop loop_obj(target_back, rtn_address);
                                if (!isLoopExist(myself)) {
                                    loop_map.emplace(myself, loop_obj);
                                    loop_map[myself].countSeen.push_back(0);
                                }
                                INS_InsertCall(cond_jump, IPOINT_BEFORE, (AFUNPTR)docount_branch_iteration, IARG_ADDRINT, myself, IARG_END);
                                if (INS_IsValidForIpointTakenBranch(ins)) {
                                    INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount_branch_invocation, IARG_ADDRINT, myself, IARG_END);
                                }
                            }
                        }
                    }

                }
            }
        }
        RTN_Close(rtn_arg);
    }
}
VOID Routine2(RTN rtn_arg, VOID* v) {
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        rtn rtn_obj(RTN_Name(rtn_arg));
        if (!isRtnExist(rtn_address)) {
            rtn_map.emplace(rtn_address, rtn_obj);
        }
        RTN_Open(rtn_arg);
        RTN_InsertCall(rtn_arg, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_ADDRINT, rtn_address, IARG_END);
        for (INS ins = RTN_InsHead(rtn_arg); INS_Valid(ins); ins = INS_Next(ins))
        {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_ADDRINT, rtn_address, IARG_END);
            if (INS_IsDirectControlFlow(ins) && !INS_IsCall(ins)) {
                ADDRINT myself = INS_Address(ins);
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
                if (target < myself) {
                    loop loop_obj(target, rtn_address);
                    if (!isLoopExist(myself)) {
                        loop_map.emplace(myself, loop_obj);
                        loop_map[myself].countSeen.push_back(0);
                    }
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_branch_iteration, IARG_ADDRINT, myself, IARG_END);
                    if (INS_Category(ins) == XED_CATEGORY_COND_BR) {
                        /* Handles 1st type loops, with single cond jump backwards. */
                        if (INS_IsValidForIpointAfter(ins)) {
                            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)docount_branch_invocation, IARG_ADDRINT, myself, IARG_END);
                        }
                    }
                    else if (INS_Category(ins) == XED_CATEGORY_UNCOND_BR) {
                        /* Handles 2nd type loops, with a single cond' jump forward
                            and a single uncond' jump backwards to the address of myself.
                        */
                        INS start = RTN_InsHead(rtn_arg);
                        for (; INS_Valid(start)&& INS_Address(start) < target; start = INS_Next(start)) {
                            ;
                        }
                        for (INS cond_jump = start; INS_Valid(cond_jump); cond_jump = INS_Next(cond_jump)) {
                            if (INS_IsDirectControlFlow(cond_jump) && !INS_IsCall(cond_jump) && INS_Category(cond_jump) == XED_CATEGORY_COND_BR
                                && INS_DirectControlFlowTargetAddress(cond_jump) > myself) {
                                if (INS_IsValidForIpointTakenBranch(cond_jump)) {
                                    INS_InsertCall(cond_jump, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount_branch_invocation, IARG_ADDRINT, myself, IARG_END);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        RTN_Close(rtn_arg);
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    std::ofstream output_file("loop-count.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, loop>> vec;
    for (auto itr = loop_map.begin(); itr != loop_map.end(); ++itr) {
        if (itr->second.countLoopInvoked) {
            vec.push_back(*itr);
        }
    }
    sort(vec.begin(), vec.end(), [=](std::pair<ADDRINT, loop>& a, std::pair<ADDRINT, loop>& b) {return a.second.totalCountSeen > b.second.totalCountSeen; });
    for (size_t i = 0; i < vec.size(); i++) {
        ADDRINT rtn_addr = vec[i].second.rtn_address;
        if (rtn_map[rtn_addr].name.find("foo") != std::string::npos) {
            std::cout << "A loop of foo was found." << std::endl;
            std::cout << "Address key: " << std::hex << vec[i].first << endl;
            std::cout << "TotalCountSeen: " << vec[i].second.totalCountSeen << std::endl;
            std::cout << "countLoopInvoked: " << vec[i].second.countLoopInvoked << std::endl;
        }
        if (vec[i].second.countLoopInvoked) {
            UINT64 mean = vec[i].second.totalCountSeen / vec[i].second.countLoopInvoked;
            UINT64 diffCount = 0;
            for (size_t j = 0; j < vec[i].second.countLoopInvoked - 1; j++) {
                if (vec[i].second.countSeen[j] != vec[i].second.countSeen[j + 1]) {
                    diffCount++;
                }
            }
            output_file << "0x" << std::hex << vec[i].second.target_address << ", " << std::dec << vec[i].second.totalCountSeen << ", "
                << vec[i].second.countLoopInvoked << ", " << mean << ", " << diffCount
                << ", " << rtn_map[rtn_addr].name << ", 0x" << std::hex << rtn_addr << ", " << std::dec
                << rtn_map[rtn_addr].ins_count << ", " << rtn_map[rtn_addr].call_count << endl;
        }
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
    
    //RTN_AddInstrumentFunction(Routine, 0);
    RTN_AddInstrumentFunction(Routine2, 0);
    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
