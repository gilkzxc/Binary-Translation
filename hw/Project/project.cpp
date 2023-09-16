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
const UINT64 heat_cold_coefficient = 1;

/* ===================================================================== */
/* Helper functions */
/* ===================================================================== */

std::vector<std::string> split(std::string const& str, const char delim)
{
    std::istringstream split(str);
    std::vector<std::string> tokens;
    for (std::string each; std::getline(split, each, delim); tokens.push_back(each));
    return tokens;
}

size_t find_str_in_vector(const std::vector<std::string>& vector_of_str, std::string str)
{   
    size_t i = 0;
    for (; i < vector_of_str.size(); i++) {
        if (vector_of_str[i] == str) {
            return i;
        }
    }
    return i;
}

ADDRINT hex_in_string_to_addrint(const std::string& str) {
    ADDRINT address;
    std::istringstream addr_in_hex(str);
    addr_in_hex >> std::hex >> address;
    return address;
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
VOID loop_profile_per_ins_instrument(INS ins, VOID* v) {
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
        if (INS_IsDirectControlFlow(ins) && !INS_IsCall(ins) && !INS_IsSyscall(ins)) {
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




VOID reorder_profile_per_trace_instrument(TRACE trace, VOID* v) {
    RTN rtn_arg = TRACE_Rtn(trace);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        //if (RTN_Name(rtn_arg) != "myMalloc" && RTN_Name(rtn_arg) != "snocString" && RTN_Name(rtn_arg) != "myfeof") {
        /*if (RTN_Name(rtn_arg) != "myMalloc" && RTN_Name(rtn_arg) != "myfeof" &&
            RTN_Name(rtn_arg) != "copyFileName" && RTN_Name(rtn_arg) != "fopen_output_safely" && RTN_Name(rtn_arg) != "main") {
            return;
        }*/
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img)) {
            return;
        }
        if (!IMG_IsMainExecutable(img)) {
            return;
        }
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            INS ins_head = BBL_InsHead(bbl);
            ADDRINT head_address = INS_Address(ins_head);
            INS ins_tail = BBL_InsTail(bbl);
            ADDRINT tail_address = INS_Address(ins_tail);
            bbl_map[head_address].tail_address = tail_address;
            bbl_map[head_address].rtn_address = rtn_address;
            if (INS_IsDirectControlFlow(ins_tail)) {
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins_tail);
                if (target > tail_address) {
                    bbl_map[head_address].jump_address = target;
                    if (INS_HasFallThrough(ins_tail)) {
                        if (INS_IsValidForIpointTakenBranch(ins_tail)) {
                            INS_InsertCall(ins_tail, IPOINT_TAKEN_BRANCH, (AFUNPTR)docount_ins, IARG_PTR, &(bbl_map[head_address].count_taken), IARG_END);
                        }
                        INS_InsertCall(ins_tail, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_PTR, &(bbl_map[head_address].count_total), IARG_END);
                        INS fall = INS_Next(ins_tail);
                        if (INS_Valid(fall)) {
                            bbl_map[head_address].fall_address = INS_Address(fall);
                        }
                    }

                }
            }
        }
    }
}



VOID reorder2_profile_per_ins_instrument(RTN rtn_arg, VOID* v) {
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img)) {
            return;
        }
        if (!IMG_IsMainExecutable(img)) {
            return;
        }
        RTN_Open(rtn_arg);
        for (INS ins = RTN_InsHead(rtn_arg); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsDirectControlFlow(ins)) {
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
                if (target > INS_Address(ins) && INS_HasFallThrough(ins)){
                    INS end_fall = INS_Next(ins);
                    for (; INS_Valid(end_fall) &&  INS_Valid(INS_Next(end_fall)) && (INS_Address(INS_Next(end_fall)) < target); end_fall = INS_Next(end_fall)) {
                        ;
                    }
                    if (INS_Valid(end_fall)) {
                        /* end_fall is the ins at the end of a fall_through. */
                        cond_br_address_to_end_of_fallthrough[INS_Address(ins)] = INS_Address(end_fall);
                    }
                    else {
                        std::cout << endl;
                    }

                }
            }
        }
        RTN_Close(rtn_arg);
    }
}

VOID inline_profile_per_ins_instrument(INS ins, VOID* v) {
    ADDRINT ins_address = INS_Address(ins);
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
        //if (rtn_obj.name == "bsW") {
        //    //rtn_map[rtn_address].do_not_translate();
        //    return;
        //}
        //if (split(rtn_obj.name, '@').size() > 1) {
        //    //rtn_map[rtn_address].do_not_translate();
        //    return;
        //}
        //REG filter_unwanted_reg_offset = INS_MemoryBaseReg(ins);
        //if (filter_unwanted_reg_offset != REG_INVALID()) {
        //    if (filter_unwanted_reg_offset == REG_RBP) {
        //        if (INS_MemoryDisplacement(ins) > 0) {
        //            //rtn_map[rtn_address].do_not_translate();
        //        }
        //    }
        //    //else if (filter_unwanted_reg_offset == REG_RSP) {
        //    //    if (INS_MemoryDisplacement(ins) < 0) {
        //    //        rtn_map[rtn_address].do_not_translate();
        //    //    }
        //    //}
        //}
        //if (INS_IsSyscall(ins)) {
        //    //rtn_map[rtn_address].do_not_translate();
        //    return;
        //}
        if (INS_IsDirectControlFlow(ins)) {
            if(INS_IsCall(ins)){
                ADDRINT target_address = INS_DirectControlFlowTargetAddress(ins);
                if (target_address == rtn_address) {
                    rtn_map[rtn_address].is_recursive = true;
                }
                else {
                    RTN target_rtn_pin = RTN_FindByAddress(target_address);
                    if (RTN_Valid(target_rtn_pin)) {
                        IMG img_target = IMG_FindByAddress(target_address);
                        if (!IMG_Valid(img_target)) {
                            return;
                        }
                        if (!IMG_IsMainExecutable(img_target)) {
                            return;
                        }
                        //std::vector<std::string> check_is_plt_from_libc = split(RTN_Name(target_rtn_pin), '@');
                        //if (check_is_plt_from_libc.size() > 1) {
                        //    //rtn_map[rtn_address].do_not_translate();
                        //    return;
                        //}
                        //rtn target_rtn(check_is_plt_from_libc[0]);
                        rtn target_rtn(RTN_Name(target_rtn_pin));
                        if (!isRtnExist(target_address)) {
                            rtn_map.emplace(target_address, target_rtn);
                        }
                        if (!rtn_map[target_address].isCallerExist(ins_address)) {
                            rtn_map[target_address].caller_map.emplace(ins_address, 0);
                        }
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_PTR,
                            &(rtn_map[target_address].caller_map[ins_address]), IARG_END);
                    }
                }
            }
        }
        else if (INS_IsIndirectControlFlow(ins)) {
            //rtn_map[rtn_address].do_not_translate();
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
                << rtn_map[rtn_addr].ins_count << ", " << rtn_map[rtn_addr].call_count << ", "
                << rtn_map[rtn_addr].is_recursive << ", " << rtn_map[rtn_addr].to_translate << endl;
        }
    }
}




bool isSingleValueExistInVector(auto vector, auto value) {
    for (auto it = vector.begin(); it != vector.end(); it++) {
        if (*it == value) {
            return true;
        }
    }
    return false;
}

std::vector <std::pair<ADDRINT, bbl>> reordered_rtn(std::map<ADDRINT, bbl> preordered) {
    std::vector <std::pair<ADDRINT, bbl>> result;
    std::vector <std::pair<ADDRINT, bbl>> blind_spots_to_be_filled;
    std::vector<ADDRINT> merged_bbl_to_be_erased;
    std::map<ADDRINT,bool> visited;
    for (auto it = preordered.begin(); it != preordered.end(); it++) {
        if (isSingleValueExistInVector(merged_bbl_to_be_erased, it->first)) {
            continue;
        }
        auto it_combine = std::next(it);
        for (; it_combine != preordered.end(); it_combine++) {
            if (isSingleValueExistInVector(merged_bbl_to_be_erased, it_combine->first)) {
                continue;
            }
            else if (it->first == it_combine->first) {
                continue;
            }
            else if (it_combine->first > it->first) {
                if (it->second.merge(it_combine->second)) {
                    merged_bbl_to_be_erased.push_back(it_combine->first);
                }
            }
            else if (it_combine->second.merge(it->second)) {
                merged_bbl_to_be_erased.push_back(it->first);
            }
        }
    }
    for (auto it = merged_bbl_to_be_erased.begin(); it != merged_bbl_to_be_erased.end(); it++) {
        //std::cout << "THIS WAS DELETED: 0x" << std::hex << *it << endl;
        preordered.erase(*it);
    }
    for (auto it = preordered.begin(); std::next(it) != preordered.end(); it++) {
        auto next = std::next(it);
        if ((it->second.tail_address + 1) < next->first) {
            bbl possible_missed_cold_code(next->first - 1);
            possible_missed_cold_code.rtn_address = it->second.rtn_address;
            blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(it->second.tail_address + 1, possible_missed_cold_code));
        }
    }
    for (auto it = blind_spots_to_be_filled.begin(); it != blind_spots_to_be_filled.end(); it++) {
        preordered[it->first] = it->second;
    }
    for (auto it = preordered.begin(); it != preordered.end(); it++) {
        visited[it->first] = false;
    }
    auto head = preordered.begin();
    while (head != preordered.end() && !visited[head->first]) {
        visited[head->first] = true;
        result.push_back(std::pair<ADDRINT, bbl>(head->first, head->second));
        //std::cout << "start: 0x" << std::hex << head->first << endl;
        //std::cout << "end: 0x" << std::hex << head->second.tail_address << endl;
        ADDRINT jump = head->second.jump_address;
        if (jump != NO_DIRECT_CONTROL_FLOW && isElementExistInMap(jump,preordered) && !visited[jump]) {
            ADDRINT fall = head->second.fall_address;
            if (fall != NO_DIRECT_CONTROL_FLOW && isElementExistInMap(fall, preordered) && !visited[fall]) {
                UINT64 count_not_taken = head->second.count_total - head->second.count_taken;
                UINT64 min_heat_releavence = heat_cold_coefficient * count_not_taken;
                if (head->second.count_taken > min_heat_releavence) {
                    /* Next in flow needs to be the jump target. */
                    head = preordered.find(jump);
                }
                else {
                    /* No reorder needed. */
                    head = preordered.find(fall);
                }
            }
            else {
                /* No reorder needed, cause it's an uncond jump. */
                head = preordered.find(jump);
            }
        }   
        else {
            auto it = std::next(head);
            for (; visited[it->first] && it != preordered.end(); it++) {
            }
            if (it == preordered.end()) {
                it = preordered.begin();
                for (; visited[it->first] && it != preordered.end(); it++) {
                }
            }
            head = it;
        }
    }
    return result;
}

VOID Fini4(INT32 code, VOID* v) {
    std::ofstream output_file("bbl-count.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, bbl>> vec;
    std::map<ADDRINT, std::map<ADDRINT, bbl>> rtn_reorder_map;
    for (auto itr = bbl_map.begin(); itr != bbl_map.end(); ++itr) {
        ADDRINT rtn_addr = itr->second.rtn_address;
        if (!isElementExistInMap(rtn_addr, rtn_reorder_map)) {
            rtn_reorder_map[rtn_addr].clear();
        }
        rtn_reorder_map[rtn_addr][itr->first] = itr->second;
    }
    std::vector<std::pair<ADDRINT, rtn>> rtn_array_sorted_by_ins_count;
    for (auto itr = rtn_map.begin(); itr != rtn_map.end(); ++itr) {
        rtn_array_sorted_by_ins_count.push_back(*itr);
    }
    sort(rtn_array_sorted_by_ins_count.begin(), rtn_array_sorted_by_ins_count.end(),
        [=](std::pair<ADDRINT, rtn>& a, std::pair<ADDRINT, rtn>& b) {return a.second.ins_count > b.second.ins_count; });
    //for (auto rtn_to_reorder = rtn_reorder_map.begin(); rtn_to_reorder != rtn_reorder_map.end(); rtn_to_reorder++) {
    for(auto rtn_it = rtn_array_sorted_by_ins_count.begin(); rtn_it != rtn_array_sorted_by_ins_count.end(); rtn_it++){
        ADDRINT dominate_caller_addr = rtn_it->second.dominate_call();
        output_file << rtn_it->second.name << ",0x" << std::hex << rtn_it->first << ","
            << std::dec << rtn_it->second.ins_count << "," << rtn_it->second.call_count << ","
            << rtn_it->second.is_recursive << ",0x" << std::hex << dominate_caller_addr << ","
            << std::dec << rtn_it->second.to_translate
            << ",start_bbl_list,";
        std::vector <std::pair<ADDRINT, bbl>> reordered;
        if (isElementExistInMap(rtn_it->first, rtn_reorder_map) && !rtn_reorder_map[rtn_it->first].empty()) {
            reordered = reordered_rtn(rtn_reorder_map[rtn_it->first]);
        }
        //std::cout << "RTN to reorder in Fini4: " << rtn_map[rtn_to_reorder->first].name << endl;
        /*int i = 0;
        for (auto shit = rtn_to_reorder->second.begin(); shit != rtn_to_reorder->second.end(); shit++) {
            std::cout << "BBL[" << std::dec << i << "]:" << endl;
            std::cout << "start: 0x" << std::hex << shit->first << endl;
            std::cout << "end: 0x" << std::hex << shit->second.tail_address << endl;
            std::cout << "count_total: " << std::dec << shit->second.count_total << endl;
            std::cout << "count_taken: " << std::dec << shit->second.count_taken << endl;
            std::cout << "jump: 0x" << std::hex << shit->second.jump_address << endl;
            std::cout << "fall: 0x" << std::hex << shit->second.fall_address << endl;
            i++;
        }*/
        /*ADDRINT dominate_caller_addr = rtn_map[rtn_to_reorder->first].dominate_call();
        output_file << rtn_map[rtn_to_reorder->first].name << ",0x" << std::hex << rtn_to_reorder->first
            << std::dec << rtn_map[rtn_to_reorder->first].ins_count << "," << rtn_map[rtn_to_reorder->first].call_count << ","
            << rtn_map[rtn_to_reorder->first].is_recursive << ",0x" << std::hex << dominate_caller_addr << std::dec
            << "," << rtn_map[rtn_to_reorder->first].to_translate

            << ",start_bbl_list,";*/
        for (size_t i = 0; i < reordered.size(); i++) {
            /*std::cout << "BBL[" << std::dec << i << "]:" << endl;
            std::cout << "start: 0x" << std::hex << reordered[i].first << endl;
            std::cout << "end: 0x" << std::hex << reordered[i].second.tail_address << endl;*/
            output_file << "0x" << std::hex << reordered[i].first << ",0x" << std::hex << reordered[i].second.tail_address  << ",";
        }
        output_file << "end_bbl_list,start_cond_end_list,";
        for (size_t i = 0; i < reordered.size(); i++) {
            ADDRINT possible_cond_br = reordered[i].second.tail_address;
            if (isElementExistInMap(possible_cond_br, cond_br_address_to_end_of_fallthrough)) {
                output_file << "0x" << std::hex << possible_cond_br << ",0x" << std::hex <<
                    cond_br_address_to_end_of_fallthrough[possible_cond_br] << ",";
            }
        }
        output_file << "end_cond_end_list" << endl;
    }
    cond_br_address_to_end_of_fallthrough.clear();
}




VOID Fini3(INT32 code, VOID* v) {
    std::ofstream output_file("rtn-output.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, rtn>> vec;
    for (auto itr = rtn_map.begin(); itr != rtn_map.end(); ++itr) {
        vec.push_back(*itr);
    }
    sort(vec.begin(), vec.end(), [=](std::pair<ADDRINT, rtn>& a, std::pair<ADDRINT, rtn>& b) {return a.second.ins_count > b.second.ins_count; });
    for (size_t i = 0; i < vec.size(); i++) {
        ADDRINT dominate_caller_addr = vec[i].second.dominate_call();
        //if (vec[i].second.name == "bsW") {
        //    std::cout << "bsW hot call site profile:" << endl;
        //    for (auto itr = vec[i].second.caller_map.begin(); itr != vec[i].second.caller_map.end(); ++itr) {
        //        std::cout << "First: 0x" << std::hex << itr->first << ", Second: " << std::dec << itr->second << endl;
        //    }
        //}
        output_file << vec[i].second.name << ", 0x" << std::hex << vec[i].first << ", "
            << std::dec << vec[i].second.ins_count << ", " << vec[i].second.call_count << ", "
            << vec[i].second.is_recursive << ", 0x" << std::hex << dominate_caller_addr << std::dec
            << ", " <<  vec[i].second.to_translate << endl;
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
    std::ifstream input_file("rtn-output.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        bool is_recursive = (bool)std::stoi(temp_line[4]), to_translate = (bool)std::stoi(temp_line[6]);
        if (is_recursive || !to_translate) {
            continue;
        }
        UINT64 ins_count = std::stoi(temp_line[2]);
        ADDRINT addr;
        std::istringstream addr_in_hex(temp_line[1]);
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



bool get_inline_functions_candidates_for_top_ten_rtn(IMG main_img) {
    std::ifstream input_file("rtn-output.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        UINT64 ins_count = std::stoi(temp_line[2]), call_count = std::stoi(temp_line[3]);
        bool is_recursive = (bool)std::stoi(temp_line[4]);
        if (is_recursive || !ins_count || !call_count) {
            continue;
        }
        ADDRINT candidate_addr, top_rtn_addr, top_call_site_addr;
        std::istringstream candidate_addr_in_hex(temp_line[1]);
        candidate_addr_in_hex >> std::hex >> candidate_addr;
        std::istringstream top_call_site_addr_in_hex(temp_line[5]);
        top_call_site_addr_in_hex >> std::hex >> top_call_site_addr;
        if (top_call_site_addr == NO_DOMINATE_CALL) {
            continue;
        }
        /* Need to exclude recursive functions, fucntion without runtime instructions and calls. */
        RTN top_rtn = RTN_FindByAddress(top_call_site_addr);
        top_rtn_addr = RTN_Address(top_rtn);
        IMG candidate_img = IMG_FindByAddress(candidate_addr), top_rtn_img = IMG_FindByAddress(top_rtn_addr);
        if (IMG_Valid(candidate_img) && IMG_IsMainExecutable(candidate_img)
            && IMG_Valid(top_rtn_img) && IMG_IsMainExecutable(top_rtn_img)) {
            if (RTN_Name(top_rtn) != "fallbackQSort3" && (RTN_Name(top_rtn) != "fallbackSort" || RTN_FindNameByAddress(candidate_addr) != "fallbackQSort3")) {
                continue;
            }
            //if(RTN_Name(top_rtn) != "compress"){
            //std::cout << "Caller: " << RTN_Name(top_rtn) << ", Callee: " << RTN_FindNameByAddress(candidate_addr) << endl;
            //if(RTN_Name(top_rtn) != "BZ2_compressBlock"){
            //    continue;
            //}
            /*if (RTN_Name(top_rtn) == "bsW" || RTN_FindNameByAddress(candidate_addr) == "bsW") {
                continue;
            }*/
            if (in_top_ten(top_rtn_addr)) {
                std::pair<ADDRINT, ADDRINT> call_site_and_candidate_addr(top_call_site_addr, candidate_addr);
                if (!isInlineCandidateExist(top_rtn_addr, call_site_and_candidate_addr)) {
                    inline_functions_candidates_for_top_ten_rtn[top_rtn_addr].push_back(call_site_and_candidate_addr);
                }
            }
        }
    }
    input_file.close();
    return true;
    //return false;
}




bool get_reorderd_rtn_map(IMG main_img) {
    std::ifstream input_file("bbl-count.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        ADDRINT rtn_address = hex_in_string_to_addrint(temp_line[1]);
        IMG img = IMG_FindByAddress(rtn_address);
        if (IMG_Valid(img)) {
            if (IMG_IsMainExecutable(img)) {
                if (!isElementExistInMap(rtn_address, reorderd_rtn_map)) {
                    reorderd_rtn_map[rtn_address].clear();
                }
                size_t start_bbl_list = find_str_in_vector(temp_line, "start_bbl_list");
                size_t end_bbl_list = find_str_in_vector(temp_line, "end_bbl_list");
                size_t start_cond_end_list = find_str_in_vector(temp_line, "start_cond_end_list");
                size_t end_cond_end_list = find_str_in_vector(temp_line, "end_cond_end_list");
                for (size_t i = start_bbl_list + 1; i < end_bbl_list; i+= 2) {
                    ADDRINT start_bbl_address = hex_in_string_to_addrint(temp_line[i]);
                    ADDRINT end_bbl_address = hex_in_string_to_addrint(temp_line[i + 1]);
                    reorderd_rtn_map[rtn_address].push_back(std::pair<ADDRINT, ADDRINT>(start_bbl_address, end_bbl_address));
                }
                for (size_t i = start_cond_end_list + 1; i < end_cond_end_list; i += 2) {
                    ADDRINT cond_br_address = hex_in_string_to_addrint(temp_line[i]);
                    ADDRINT end_fall_address = hex_in_string_to_addrint(temp_line[i + 1]);
                    cond_br_address_to_end_of_fallthrough[cond_br_address] = end_fall_address;
                }

            }
        }
    }
    input_file.close();
    /*std::cout << "reorderd_rtn_map.size(): " << std::dec << reorderd_rtn_map.size() << endl;
    for (auto it = reorderd_rtn_map.begin(); it != reorderd_rtn_map.end(); it++) {
        std::cout << "The planned reorder of function at address: 0x" << std::hex << it->first << ", with vector size: "
            << std::dec << it->second.size() << endl;
        for (size_t i = 0; i < it->second.size(); i++) {
            std::cout << "BBL [" << i << "]: start: 0x" << std::hex << it->second[i].first << " ,end: 0x" << std::hex << it->second[i].second;
            if (isElementExistInMap(it->second[i].second, cond_br_address_to_end_of_fallthrough)) {
                std::cout << ", end_fall: 0x" << std::hex << cond_br_address_to_end_of_fallthrough[it->second[i].second];
            }
            std::cout << endl;
        }
    }*/
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
    if (!get_inline_functions_candidates_for_top_ten_rtn(img)) {
        return;
    }
    if (!get_reorderd_rtn_map(img)) {
        return;
    }
    /*if (!get_top_ten_jumps(img)) {
        return;
    }*/
    int rc = 0;

    // step 2: Check size of executable sections and allocate required memory:	
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;


    // Step 3: go over all routines and identify candidate routines and copy their code into the instr map IR:
    //rc = find_candidate_rtns_for_translation(img);
    rc = find_candidate_rtns_for_translation2(img);
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
        INS_AddInstrumentFunction(loop_profile_per_ins_instrument, 0);
        TRACE_AddInstrumentFunction(reorder_profile_per_trace_instrument, 0);
        RTN_AddInstrumentFunction(reorder2_profile_per_ins_instrument, 0);
        INS_AddInstrumentFunction(inline_profile_per_ins_instrument, 0);
        //PIN_AddFiniFunction(Fini, 0);
        //PIN_AddFiniFunction(Fini3, 0);
        PIN_AddFiniFunction(Fini4, 0);
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
