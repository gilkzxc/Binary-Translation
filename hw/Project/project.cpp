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
#include "rtn-translation.cpp"
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
class branch {
public:
    ADDRINT target_address;
    UINT64 run_count;
    UINT64 jump_count;
    UINT64 hot_count;
    bool is_taken_hot;
    branch() :target_address((ADDRINT)0), run_count(0), jump_count(0), hot_count(0), is_taken_hot(false) {}
    branch(ADDRINT target_addr) :target_address(target_addr), run_count(0), jump_count(0), hot_count(0), is_taken_hot(false) {}
    ~branch() {}
};
static std::map<ADDRINT, rtn> rtn_map;
static std::map<ADDRINT, loop> loop_map;
std::map<ADDRINT, branch> branch_map;

/* ===================================================================== */
/* Helper functions */
/* ===================================================================== */
bool isRtnExist(ADDRINT rtn_address) {
    return (!(rtn_map.find(rtn_address) == rtn_map.end()));
}
bool isLoopExist(ADDRINT loop_address) {
    return (!(loop_map.find(loop_address) == loop_map.end()));
}
bool isBranchExist(ADDRINT branch_address) {
    return (!(branch_map.find(branch_address) == branch_map.end()));
}
std::vector<std::string> split(std::string const& str, const char delim)
{
    std::istringstream split(str);
    std::vector<std::string> tokens;
    for (std::string each; std::getline(split, each, delim); tokens.push_back(each));
    return tokens;
}


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

/* ===================================================================== */
/* Analysis functions */
/* ===================================================================== */
VOID docount_ins(UINT64* ptr_ins) {
    (*ptr_ins)++;
}
VOID docount_rtn(UINT64* ptr_call) {
    (*ptr_call)++;
}
VOID docount_branch_iteration(ADDRINT loop_address) {
    loop_map[loop_address].countSeen[loop_map[loop_address].countLoopInvoked]++;
    loop_map[loop_address].totalCountSeen++;
}
VOID docount_branch_invocation(UINT64* ptr_invoked, std::vector<UINT64>* ptr_countSeenArray) {
    (*ptr_invoked)++;
    (*ptr_countSeenArray).push_back(0);
}
/* ===================================================================== */

/*
* Instruction instrument function:
*   For every instruction in the trace, the function will insert analysis docount functions.
*   Per routine, the function will insert instruction counter and routine calls counter.
*   In addition, the function will instrument loops. As jumps backwards symbolise iteration of a loop.
*   Also, count invocation when loops exit, and collect additional info to be analyze at FINI().
*   
*/
VOID Instruction(INS ins, VOID* v) {
    RTN rtn_arg = INS_Rtn(ins);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img)) {
            return;
        }
        if (!IMG_IsMainExecutable(img)) {
            return;
        }
        rtn rtn_obj(RTN_Name(rtn_arg));
        if (!isRtnExist(rtn_address)) {
            rtn_map.emplace(rtn_address, rtn_obj);
        }
        if (rtn_address == INS_Address(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_PTR, &(rtn_map[rtn_address].call_count), IARG_END);
        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_PTR, &(rtn_map[rtn_address].ins_count), IARG_END);
        if (INS_IsDirectControlFlow(ins) && !INS_IsCall(ins)) {
            ADDRINT myself = INS_Address(ins);
            ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
            if (target < myself) {
                loop loop_obj(target, rtn_address);
                if (!isLoopExist(myself)) {
                    loop_map.emplace(myself, loop_obj);
                    loop_map[myself].countSeen.push_back(0);
                }
                if (INS_Category(ins) == XED_CATEGORY_COND_BR) {
                    /* Handles 1st type loops, with single cond jump backwards. */
                    if (INS_IsValidForIpointTakenBranch(ins)) {
                        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount_branch_iteration, IARG_ADDRINT, myself, IARG_END);
                    }
                    if (INS_IsValidForIpointAfter(ins)) {
                        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)docount_branch_invocation, IARG_PTR,
                            &(loop_map[myself].countLoopInvoked), IARG_PTR, &(loop_map[myself].countSeen), IARG_END);
                    }
                }
                else if (INS_Category(ins) == XED_CATEGORY_UNCOND_BR) {
                    /* Handles 2nd type loops, with a single cond' jump forward
                        and a single uncond' jump backwards to the address of myself.
                    */
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_branch_iteration, IARG_ADDRINT, myself, IARG_END);
                    RTN_Open(rtn_arg);
                    INS start = RTN_InsHead(rtn_arg);
                    for (; INS_Valid(start) && INS_Address(start) < target; start = INS_Next(start)) {
                        ;
                    }
                    for (INS cond_jump = start; INS_Valid(cond_jump); cond_jump = INS_Next(cond_jump)) {
                        if (INS_IsDirectControlFlow(cond_jump) && !INS_IsCall(cond_jump) && INS_Category(cond_jump) == XED_CATEGORY_COND_BR
                            && INS_DirectControlFlowTargetAddress(cond_jump) > myself) {
                            if (INS_IsValidForIpointTakenBranch(cond_jump)) {
                                INS_InsertCall(cond_jump, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount_branch_invocation, IARG_PTR,
                                    &(loop_map[myself].countLoopInvoked), IARG_PTR, &(loop_map[myself].countSeen), IARG_END);
                            }
                            break;
                        }
                    }
                    RTN_Close(rtn_arg);
                }
            }
        }
    }
}

VOID Instruction2(INS ins, VOID* v) {
    RTN rtn_arg = INS_Rtn(ins);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img)) {
            return;
        }
        if (!IMG_IsMainExecutable(img)) {
            return;
        }
        rtn rtn_obj(RTN_Name(rtn_arg));
        if (!isRtnExist(rtn_address)) {
            rtn_map.emplace(rtn_address, rtn_obj);
        }
        if (rtn_address == INS_Address(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_PTR, &(rtn_map[rtn_address].call_count), IARG_END);
        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_PTR, &(rtn_map[rtn_address].ins_count), IARG_END);
        if (INS_IsDirectControlFlow(ins) && !INS_IsCall(ins)) {
            ADDRINT myself = INS_Address(ins);
            ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
            branch branch_obj(target);
            if (!isBranchExist(myself)) {
                branch_map.emplace(myself, branch_obj);
            }
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_PTR, &(branch_map[myself].run_count), IARG_END);
            if (INS_IsValidForIpointTakenBranch(ins)) {
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount_ins, IARG_PTR, &(branch_map[myself].jump_count), IARG_END);
            }
        }
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
VOID Fini2(INT32 code, VOID* v) {
    std::ofstream output_file("count.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, branch>> vec;
    for (auto itr = branch_map.begin(); itr != branch_map.end(); ++itr) {
        UINT64 delta = itr->second.run_count - itr->second.jump_count;
        if (itr->second.jump_count > delta) {
            itr->second.hot_count = itr->second.jump_count;
            itr->second.is_taken_hot = true;
        }
        else {
            itr->second.hot_count = delta;
            itr->second.is_taken_hot = false;
        }
        vec.push_back(*itr);
    }
    sort(vec.begin(), vec.end(), [=](std::pair<ADDRINT, branch>& a, std::pair<ADDRINT, branch>& b) {return a.second.hot_count > b.second.hot_count; });
    for (size_t i = 0; i < vec.size(); i++) {
        output_file << "0x" << std::hex << vec[i].first << ", 0x" << std::hex << vec[i].second.target_address << ", "
            << std::dec << vec[i].second.run_count << ", " << vec[i].second.jump_count << ", " << vec[i].second.is_taken_hot << endl;
    }
}
/* ===================================================================== */


/* ===================================================================== */
/* Probe Mode */
/* ===================================================================== */

/* ===================================================================== */
/*
*   get_top_ten_rtn function:
*       The function fetches from the csv file, the top 10 in number of instructions of routines
*       from the main executable image. The result is inserted into top_ten_rtn vector.
*/
bool get_top_ten_rtn(IMG main_img) {
    std::ifstream input_file("loop-count.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        UINT64 ins_count = std::stoi(temp_line[7]);
        ADDRINT addr;
        std::istringstream addr_in_hex(temp_line[6]);
        addr_in_hex >> std::hex >> addr;
        IMG img = IMG_FindByAddress(addr);
        if (IMG_Valid(img)) {
            if (IMG_IsMainExecutable(img)) {
                if (!in_top_ten(addr)) {
                    if (top_ten_rtn.size() < 10) {
                        top_ten_rtn.push_back(std::pair<ADDRINT, UINT64>(addr, ins_count));
                        sort(top_ten_rtn.begin(), top_ten_rtn.end(), [=](std::pair<ADDRINT, UINT64>& a, std::pair<ADDRINT, UINT64>& b) {return a.second < b.second; });
                    }
                    else {
                        if (ins_count > top_ten_rtn[0].second) {
                            top_ten_rtn.erase(top_ten_rtn.begin());
                            top_ten_rtn.push_back(std::pair<ADDRINT, UINT64>(addr, ins_count));
                            sort(top_ten_rtn.begin(), top_ten_rtn.end(), [=](std::pair<ADDRINT, UINT64>& a, std::pair<ADDRINT, UINT64>& b) {return a.second < b.second; });
                        }
                    }
                }
            }
        }
    }
    input_file.close();
    return true;
}
/* ===================================================================== */

/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID* v)
{
    // debug print of all images' instructions
    //dump_all_image_instrs(img);


    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
        return;
    // Step 1: Fetch top ten routines. On failer exit ImageLoad.
    if (!get_top_ten_rtn(img)) {
        return;
    }
    int rc = 0;

    // step 2: Check size of executable sections and allocate required memory:	
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;


    // Step 3: go over all routines and identify candidate routines and copy their code into the instr map IR:
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0)
        return;

    cout << "after identifying candidate routines" << endl;

    // Step 4: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    rc = chain_all_direct_br_and_call_target_entries();
    if (rc < 0)
        return;

    cout << "after calculate direct br targets" << endl;

    // Step 5: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0)
        return;

    cout << "after fix instructions displacements" << endl;


    // Step 6: write translated routines to new tc:
    rc = copy_instrs_to_tc();
    if (rc < 0)
        return;

    cout << "after write all new instructions to memory tc" << endl;

    if (KnobDumpTranslatedCode) {
        cerr << "Translation Cache dump:" << endl;
        dump_tc();  // dump the entire tc

        cerr << endl << "instructions map dump:" << endl;
        dump_entire_instr_map();     // dump all translated instructions in map_instr
    }


    // Step 7: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
        commit_translated_routines();
        cout << "after commit translated routines" << endl;
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
    if (KnobInst) {
        /* Probe Mode */
        // Register ImageLoad
        IMG_AddInstrumentFunction(ImageLoad, 0);
        // Start the program, never returns
        PIN_StartProgramProbed();
    }
    else if (KnobProf) {
        /* JIT Mode */
        INS_AddInstrumentFunction(Instruction2, 0);
        PIN_AddFiniFunction(Fini2, 0);
        // Never returns
        PIN_StartProgram();
    }
    else {
        PIN_StartProgram();
    }
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
