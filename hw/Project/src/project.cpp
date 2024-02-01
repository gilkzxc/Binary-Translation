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

UINT64 heat_cold_coefficient = 1;
size_t MAX_NUM_OF_TOP_RTN = 20;

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

bool isSingleValueExistInVector(auto vector, auto value) {
    for (auto it = vector.begin(); it != vector.end(); it++) {
        if (*it == value) {
            return true;
        }
    }
    return false;
}

/* reordered_rtn:
*   Takes the profile traces of basic blocks, and create a new order, such that will bring the hot code to the top of the routine.
*   begin_cold_code_first, is an output parameter that holds the start of the cold area of the new reorderd routine.
*   That is needed when we do a inline+reorder.
*   We sort the filterd preorderd with a greedy algorithm over the control flow graph traversal.
*   We use an in-order traversal. Worst case complexity of O(VE), where V is the vertecies and E is the edges.
**/
std::vector <std::pair<ADDRINT, bbl>> reordered_rtn(std::map<ADDRINT, bbl> preordered, ADDRINT& begin_cold_code_first) {
    std::vector <std::pair<ADDRINT, bbl>> result;
    std::vector <std::pair<ADDRINT, bbl>> blind_spots_to_be_filled;
    std::vector<ADDRINT> merged_bbl_to_be_erased;
    std::map<ADDRINT, bool> visited;
    /* Merging multiple basic blocks that ends with same tail, and keep the one with the topest head address. */
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
        preordered.erase(*it);
    }
    /* As PIN go over the function in TRACE-BBL instrumentation. It's sometimes misses very cold code. */
    /* By creating "imaginary" blocks, we fill the holes in the preordered of missing cold code. */
    auto it_miss = preordered.begin();
    for (; std::next(it_miss) != preordered.end(); it_miss++) {
        auto next = std::next(it_miss);
        if ((it_miss->second.tail_address + 1) < next->first) {
            bbl possible_missed_cold_code(next->first - 1);
            possible_missed_cold_code.rtn_address = it_miss->second.rtn_address;
            blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(it_miss->second.tail_address + 1, possible_missed_cold_code));
        }
    }
    if (it_miss != preordered.end() && std::next(it_miss) == preordered.end()) {
        ADDRINT rtn_address = it_miss->second.rtn_address;
        if (rtn_map[rtn_address].tail_address != (ADDRINT)0 &&
            rtn_map[rtn_address].tail_address > it_miss->second.tail_address) {
            bbl possible_missed_cold_code(rtn_map[rtn_address].tail_address);
            possible_missed_cold_code.rtn_address = rtn_address;
            blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(it_miss->second.tail_address + 1, possible_missed_cold_code));
        }
    }
    for (auto it = blind_spots_to_be_filled.begin(); it != blind_spots_to_be_filled.end(); it++) {
        preordered[it->first] = it->second;
    }
    /* We mark before all the filterd basic blocks as unvisited. */
    for (auto it = preordered.begin(); it != preordered.end(); it++) {
        visited[it->first] = false;
    }
    /* The traversal algorithm. */
    auto head = preordered.begin();
    while (head != preordered.end() && !visited[head->first]) {
        /* Each node that wasn't visited is inserted into the new result order. */
        visited[head->first] = true;
        result.push_back(std::pair<ADDRINT, bbl>(head->first, head->second));
        ADDRINT jump = head->second.jump_address;
        if (jump != NO_DIRECT_CONTROL_FLOW && isElementExistInMap(jump, preordered) && !visited[jump]) {
            /* If we see a jump, we check if we need/should reorder the coming code. */
            /* By moving up hotter code that is the target of the jump and replacing it with the cold coming code. */
            ADDRINT fall = head->second.fall_address;
            UINT64 count_not_taken = head->second.count_total - head->second.count_taken;
            UINT64 min_heat_releavence = heat_cold_coefficient * count_not_taken;
            if (fall != NO_DIRECT_CONTROL_FLOW && isElementExistInMap(fall, preordered) && !visited[fall]) {
                /* Repleacement is more releveant as this is a condintional jump. */
                if (head->second.count_taken > min_heat_releavence) {
                    /* Next in flow needs to be the jump target. */
                    head = preordered.find(jump);
                }
                else {
                    /* No reorder needed. */
                    head = preordered.find(fall);
                }
            }
            else if(head->second.count_total && head->second.count_taken && head->second.count_taken > min_heat_releavence){
                /* Didn't recognise fall, brings jump closer only when should. */
                head = preordered.find(jump);
            }
            else {
                /* Go visit the next block in the function flow. */
                auto it = std::next(head);
                for (; visited[it->first] && it != preordered.end(); it++) {
                }
                if (it == preordered.end()) {
                    /* Flow trace has reached it's end. Chose a new trace to build. */
                    it = preordered.begin();
                    for (; visited[it->first] && it != preordered.end(); it++) {
                    }
                }
                head = it;
            }
        }
        else {
            /* Go visit the next block in the function flow. */
            auto it = std::next(head);
            for (; visited[it->first] && it != preordered.end(); it++) {
            }
            if (it == preordered.end()) {
                /* Flow trace has reached it's end. Chose a new trace to build. */
                it = preordered.begin();
                for (; visited[it->first] && it != preordered.end(); it++) {
                }
            }
            head = it;
        }
    }
    /* Catching the end of the hottest trace and the begin of the first colder trace. */
    auto r = result.begin();
    for (; std::next(r) != result.end() && r->second.tail_address < std::next(r)->first; r++) {
        ;
    }
    if (r != result.end()) {
        r++;
        begin_cold_code_first = r->first;
    }
    return result;
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
/* ===================================================================== */

/*
* Instruction instrument function:
*   For every instruction in the trace, the function will insert analysis docount functions.
*   Per routine, the function will insert instruction counter and routine calls counter.
*   
*/

/* Filtering irreleavent functions for inline. */
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
        if (rtn_address == INS_Address(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_PTR, &(rtn_map[rtn_address].call_count), IARG_END);
        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, IARG_PTR, &(rtn_map[rtn_address].ins_count), IARG_END);
        REG filter_unwanted_reg_offset = INS_MemoryBaseReg(ins);
        if (filter_unwanted_reg_offset != REG_INVALID()) {
            if (filter_unwanted_reg_offset == REG_RBP) {
                if (INS_MemoryDisplacement(ins) > 0) {
                    rtn_map[rtn_address].do_not_inline();
                }
            }
            //else if (filter_unwanted_reg_offset == REG_RSP) {
            //    if (INS_MemoryDisplacement(ins) != 0) {
            //        rtn_map[rtn_address].do_not_inline();
            //    }
            //    //rtn_map[rtn_address].do_not_inline();
            //}
        }
        //if (INS_IsSyscall(ins)) {
        //    //rtn_map[rtn_address].do_not_translate();
        //    return;
        //}
        if (INS_IsDirectControlFlow(ins)) {
            if (INS_IsCall(ins)) {
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


VOID reorder_profile_per_trace_instrument(TRACE trace, VOID* v) {
    RTN rtn_arg = TRACE_Rtn(trace);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
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
                    for (; INS_Valid(end_fall) &&  INS_Valid(INS_Next(end_fall)) && (INS_Address(INS_Next(end_fall)) < target);
                        end_fall = INS_Next(end_fall)) {
                        ;
                    }
                    if (INS_Valid(end_fall)) {
                        /* end_fall is the ins at the end of a fall_through. */
                        cond_br_address_to_end_of_fallthrough[INS_Address(ins)] = INS_Address(end_fall);
                    }

                }
            }
        }
        INS rtn_tail = RTN_InsTail(rtn_arg);
        if (INS_Valid(rtn_tail)) {
            rtn rtn_obj(RTN_Name(rtn_arg));
            if (!isRtnExist(rtn_address)) {
                rtn_map.emplace(rtn_address, rtn_obj);
            }
            rtn_map[rtn_address].tail_address = INS_Address(rtn_tail);
        }
        RTN_Close(rtn_arg);
    }
}


/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    std::ofstream output_file("count.csv", std::ofstream::out);
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
    for(auto rtn_it = rtn_array_sorted_by_ins_count.begin(); rtn_it != rtn_array_sorted_by_ins_count.end(); rtn_it++){
        ADDRINT dominate_caller_addr = rtn_it->second.dominate_call();
        output_file << rtn_it->second.name << ",0x" << std::hex << rtn_it->first << ","
            << std::dec << rtn_it->second.ins_count << "," << rtn_it->second.call_count << ","
            << rtn_it->second.is_recursive << ",0x" << std::hex << dominate_caller_addr << ","
            << std::dec << rtn_it->second.to_inline << ",";
            
        std::vector <std::pair<ADDRINT, bbl>> reordered;
        ADDRINT begin_cold_code_first = (ADDRINT)0;
        if (isElementExistInMap(rtn_it->first, rtn_reorder_map) && !rtn_reorder_map[rtn_it->first].empty()) {
            reordered = reordered_rtn(rtn_reorder_map[rtn_it->first], begin_cold_code_first);
        }
        output_file << "0x" << std::hex << begin_cold_code_first << ",start_bbl_list,";
        for (size_t i = 0; i < reordered.size(); i++) {
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


/* ===================================================================== */

/* ===================================================================== */
/* Probe Mode */
/* ===================================================================== */

/* ===================================================================== */
/*
*   get_top_rtn function:
*       The function fetches from the csv file, the top routine in number of instructions of routines
*       from the main executable image. The result is inserted into top_rtn vector.
*/
bool get_top_rtn(IMG main_img) {
    std::ifstream input_file("count.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        bool is_recursive = (bool)std::stoi(temp_line[4]), to_inline = (bool)std::stoi(temp_line[6]);
        if (is_recursive || !to_inline) {
            continue;
        }
        UINT64 ins_count = std::stoi(temp_line[2]);
        ADDRINT addr = hex_in_string_to_addrint(temp_line[1]);
        IMG img = IMG_FindByAddress(addr);
        if (IMG_Valid(img)) {
            if (IMG_IsMainExecutable(img)) {
                if (!isTopRtn(addr)) {
                    if (top_rtn.size() < MAX_NUM_OF_TOP_RTN) {
                        top_rtn[addr] = ins_count;
                    }
                }
            }
        }
    }
    input_file.close();
    return true;
}

/* Fetechs the profile of previous run. */
bool get_reorderd_rtn_map_and_inline_functions_candidates_for_top_rtn(IMG main_img) {
    std::ifstream input_file("count.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        ADDRINT rtn_address = hex_in_string_to_addrint(temp_line[1]);
        UINT64 ins_count = std::stoi(temp_line[2]), call_count = std::stoi(temp_line[3]);
        bool is_recursive = (bool)std::stoi(temp_line[4]), to_inline = (bool)std::stoi(temp_line[6]);
        ADDRINT top_call_site_addr = hex_in_string_to_addrint(temp_line[5]), top_rtn_addr;
        ADDRINT begin_cold_code_first = hex_in_string_to_addrint(temp_line[7]);
        IMG img = IMG_FindByAddress(rtn_address);
        if (IMG_Valid(img)) {
            if (IMG_IsMainExecutable(img)) {
                if (!isElementExistInMap(rtn_address, reorderd_rtn_map)) {
                    reorderd_rtn_map[rtn_address].clear();
                }
                if (begin_cold_code_first != (ADDRINT)0) {
                    rtn_begin_cold_code[rtn_address] = begin_cold_code_first;
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
        if (top_call_site_addr != NO_DOMINATE_CALL && (!is_recursive && ins_count && call_count && to_inline)) {
            /* Need to exclude recursive functions, fucntion without runtime instructions and calls. */
            ADDRINT candidate_addr = rtn_address;
            RTN top_rtn = RTN_FindByAddress(top_call_site_addr);
            top_rtn_addr = RTN_Address(top_rtn);
            IMG candidate_img = IMG_FindByAddress(candidate_addr), top_rtn_img = IMG_FindByAddress(top_rtn_addr);
            if (IMG_Valid(candidate_img) && IMG_IsMainExecutable(candidate_img)
                && IMG_Valid(top_rtn_img) && IMG_IsMainExecutable(top_rtn_img)) {
                if (RTN_Name(top_rtn) != "fallbackQSort3" &&
                    (RTN_Name(top_rtn) != "fallbackSort" || RTN_FindNameByAddress(candidate_addr) != "fallbackQSort3")
                    && (RTN_Name(top_rtn) != "generateMTFValues" || RTN_FindNameByAddress(candidate_addr) != "makeMaps_e")){
                    continue;
                }
                if (isTopRtn(top_rtn_addr)) {
                    std::pair<ADDRINT, ADDRINT> call_site_and_candidate_addr(top_call_site_addr, candidate_addr);
                    if (!isInlineCandidateExist(top_rtn_addr, call_site_and_candidate_addr)) {
                        inline_functions_candidates_for_top_rtn[top_rtn_addr].push_back(call_site_and_candidate_addr);
                    }
                }
            }
        }
    }
    input_file.close();
    if (KnobDebug) {
        for (auto it = inline_functions_candidates_for_top_rtn.begin(); it != inline_functions_candidates_for_top_rtn.end(); it++) {
            std::cout << "Caller: " << RTN_FindNameByAddress(it->first) << endl;
            for (auto itt = it->second.begin(); itt != it->second.end(); itt++) {
                std::cout << "Callee: " << RTN_FindNameByAddress(itt->second) << endl;
            }
        }
        for (auto it = reorderd_rtn_map.begin(); it != reorderd_rtn_map.end(); it++) {
            std::cout << "The planned reorder of function at address: 0x" << std::hex << it->first << ", with vector size: "
                << std::dec << it->second.size() << endl;
            for (size_t i = 0; i < it->second.size(); i++) {
                std::cout << "BBL [" << std::dec << i << "]: start: 0x" << std::hex << it->second[i].first << " ,end: 0x" << std::hex << it->second[i].second;
                if (isElementExistInMap(it->second[i].second, cond_br_address_to_end_of_fallthrough)) {
                    std::cout << ", end_fall: 0x" << std::hex << cond_br_address_to_end_of_fallthrough[it->second[i].second];
                }
                std::cout << endl;
            }
        }
    }
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
    // Step 1: Fetch profile of program. On failer exit ImageLoad.
    if (!get_top_rtn(img)) {
        return;
    }
    if (!get_reorderd_rtn_map_and_inline_functions_candidates_for_top_rtn(img)) {
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
        // Command line arguments. To find the right coefficients.
        //heat_cold_coefficient = KnobHeatCoeff;
        MAX_NUM_OF_TOP_RTN = KnobMaxNumTopRTN;
        // Register ImageLoad
        IMG_AddInstrumentFunction(ImageLoad, 0);
        // Start the program, never returns
        PIN_StartProgramProbed();
    }
    else if (KnobProf) {
        /* JIT Mode */
        // Command line arguments. To find the right coefficients.
        heat_cold_coefficient = KnobHeatCoeff;
        INS_AddInstrumentFunction(inline_profile_per_ins_instrument, 0);
        TRACE_AddInstrumentFunction(reorder_profile_per_trace_instrument, 0);
        RTN_AddInstrumentFunction(reorder2_profile_per_ins_instrument, 0);
        PIN_AddFiniFunction(Fini, 0);
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
