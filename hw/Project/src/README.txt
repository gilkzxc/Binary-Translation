Final Project pintool:
	In this pintool we try to optimise Bzip2 by using inlinig functions and reordering them afterwards.
	Reached Nested inlinig with the hot functions: fallbackSimpleSort, fallbackQ3Sort, fallbackSort.
	And regulare inlining with another example.
	Have reached reordering all functions in Bzip2.

Profile explaination:
	The count.csv file contains a list of all routines,
	 sorted from the hottest routines and down by instruction count.
	First field is the name of the routine, second is it's address.
	3rd is the instruction count while 4th is the call count.
	5th is to recognise a recorsive function which we want to ignore in inlining. (1 is recursive 0 is not.)
	6th is the address of the most dominate hot call site call instruction of the routine in the line.
	Meaing it's the call instruction address that calls the most to the routine in the line.
	7th is general info if to not inline the function at all. (1 is to inline 0 is not.)
	8th is the end of the hottest trace in the reorderd routine form and the begining of it's cold area.
	From start_bbl_list we pass the new order of the basic blocks of the routine accourding to the collected profile.
	Until end_bbl_list. In pairs: start of block, tail of block.
	From start_cond_end_list, untill end_cond_end_list,
	 we pass in pairs the area of the fallthrough for the releveant conditional jumps.
	The instruction address of the jump itself and the address of the last fallthrough instruction.
	(The last FT instruction is the one that is right before the target address pre-reorder.)

 

Compiling and linking command:
make PIN_ROOT=<pin-root folder> project.test

Running the pintool command(without recompiling):
<pin-root folder>/pin -t ./project.so <running mode> --  <path to application and commandline arguments>
Running the pintool command(with recompiling):
<pin-root folder>/pin -t ./obj-intel64/project.so <running mode> --  <path to application and commandline arguments>

For example to run the pin tool in profile collecting mode on bzip2:
<pindir>/pin -t project.so –prof -- ./bzip2 –k -f input.txt
For example to run the pin tool in optimization mode on the same bzip3
<pindir>/pin -t project.so –opt -- ./bzip2 –k -f input.txt	

For seeing releveant debugging messages and info, use additionaly -debug flag in either of the modes.

